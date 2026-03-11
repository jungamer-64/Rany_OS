// ============================================================================
// drivers/mlx5/src/structs/cmd.rs - Command Mailbox Layouts
// ============================================================================

use crate::structs::{get_bits_u32, get_bits_u64, set_bits_u32, set_bits_u64};

/// MKEY Context Layout
pub struct MkeyContextLayout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> MkeyContextLayout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }

    // Legacy access_flags helper using the resource flag definitions
    // (bit0=LR, bit1=LW, bit2=RR, bit3=RW).
    pub fn set_access_flags(&mut self, val: u8) {
        self.set_lr((val & 0x01) != 0);
        self.set_lw((val & 0x02) != 0);
        self.set_rr((val & 0x04) != 0);
        self.set_rw((val & 0x08) != 0);
    }
    // rw: bit 18
    pub fn set_rw(&mut self, val: bool) {
        set_bits_u32(self.data, 18, 1, if val { 1 } else { 0 });
    }
    // rr: bit 19
    pub fn set_rr(&mut self, val: bool) {
        set_bits_u32(self.data, 19, 1, if val { 1 } else { 0 });
    }
    // lw: bit 20
    pub fn set_lw(&mut self, val: bool) {
        set_bits_u32(self.data, 20, 1, if val { 1 } else { 0 });
    }
    // lr: bit 21
    pub fn set_lr(&mut self, val: bool) {
        set_bits_u32(self.data, 21, 1, if val { 1 } else { 0 });
    }
    // access_mode_1_0: bits 22-23
    pub fn set_access_mode_1_0(&mut self, val: u8) {
        set_bits_u32(self.data, 22, 2, val as u32);
    }
    // relaxed_ordering_write: bit 13
    pub fn set_relaxed_ordering_write(&mut self, val: bool) {
        set_bits_u32(self.data, 13, 1, if val { 1 } else { 0 });
    }
    // qpn: bits 32-55
    pub fn set_qpn(&mut self, val: u32) {
        set_bits_u32(self.data, 32, 24, val);
    }
    // translations_octword_size: bits 416-447
    pub fn set_translations_octword_size(&mut self, val: u32) {
        set_bits_u32(self.data, 416, 32, val);
    }
    // PD: bits 104-127
    pub fn set_pd(&mut self, val: u32) {
        set_bits_u32(self.data, 104, 24, val);
    }
    // start_addr: bits 128-191
    pub fn set_start_addr(&mut self, val: u64) {
        set_bits_u64(self.data, 128, val);
    }
    // byte_count: bits 192-255
    pub fn set_len(&mut self, val: u64) {
        set_bits_u64(self.data, 192, val);
    }
    // length64: bit 96
    pub fn set_length64(&mut self, val: bool) {
        set_bits_u32(self.data, 96, 1, if val { 1 } else { 0 });
    }
    // log_page_size: bits 474-479
    pub fn set_log_page_size(&mut self, val: u32) {
        set_bits_u32(self.data, 474, 6, val);
    }
    // relaxed_ordering_read: bit 473
    pub fn set_relaxed_ordering_read(&mut self, val: bool) {
        set_bits_u32(self.data, 473, 1, if val { 1 } else { 0 });
    }
    // mkey_7_0: bits 56-63
    pub fn set_mkey_7_0(&mut self, val: u8) {
        set_bits_u32(self.data, 56, 8, val as u32);
    }
}

/// TIS Context Layout
pub struct TisContextLayout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> TisContextLayout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }

    // lag_tx_port_affinity: bits 4-7 (dword 0)
    pub fn set_lag_tx_port_affinity(&mut self, val: u8) {
        set_bits_u32(self.data, 4, 4, val as u32);
    }
    // strict_lag_tx_port_affinity: bit 0 (dword 0)
    pub fn set_strict_lag_tx_port_affinity(&mut self, val: bool) {
        set_bits_u32(self.data, 0, 1, if val { 1 } else { 0 });
    }
    // prio: bits 12-15 (dword 0)
    pub fn set_prio(&mut self, val: u8) {
        set_bits_u32(self.data, 12, 4, val as u32);
    }
    // transport_domain: bit 296-319 (byte 37-39)
    pub fn set_transport_domain(&mut self, val: u32) {
        set_bits_u32(self.data, 296, 24, val);
    }
    // pd: bit 360-383 (byte 45-47)
    pub fn set_pd(&mut self, val: u32) {
        set_bits_u32(self.data, 360, 24, val);
    }
    // underlay_qpn: bit 328-351 (byte 41-43)
    pub fn set_underlay_qpn(&mut self, val: u32) {
        set_bits_u32(self.data, 328, 24, val);
    }
}

/// TIR Context Layout
pub struct TirContextLayout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> TirContextLayout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }

    // disp_type: bits 32-35 (dword 1)
    pub fn set_disp_type(&mut self, val: u8) {
        set_bits_u32(self.data, 32, 4, val as u32);
    }
    // inline_rqn: bits 232-255 (dword 7)
    pub fn set_inline_rqn(&mut self, val: u32) {
        set_bits_u32(self.data, 232, 24, val);
    }
    // indirect_table: bits 264-287 (dword 8)
    pub fn set_indirect_table(&mut self, val: u32) {
        set_bits_u32(self.data, 264, 24, val);
    }
    // rx_hash_fn: bits 288-291 (dword 9)
    pub fn set_rx_hash_fn(&mut self, val: u8) {
        set_bits_u32(self.data, 288, 4, val as u32);
    }
    // transport_domain: bits 296-319
    pub fn set_transport_domain(&mut self, val: u32) {
        set_bits_u32(self.data, 296, 24, val);
    }

    // LRO settings
    pub fn set_lro_enable_mask(&mut self, val: u8) {
        set_bits_u32(self.data, 148, 4, val as u32);
    }
    pub fn set_lro_max_ip_payload_size(&mut self, val: u32) {
        set_bits_u32(self.data, 152, 8, val);
    }
    pub fn set_lro_timeout_period_usecs(&mut self, val: u16) {
        set_bits_u32(self.data, 132, 16, val as u32);
    }
}

/// ENABLE_HCA Input Layout
pub struct EnableHcaInputLayout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> EnableHcaInputLayout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }
    pub fn set_function_id(&mut self, val: u16) {
        set_bits_u32(self.data, 80, 16, val as u32);
    }
}

/// INIT_HCA Input Layout
pub struct InitHcaInputLayout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> InitHcaInputLayout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }
    pub fn set_sw_vhca_id(&mut self, val: u16) {
        set_bits_u32(self.data, 96, 16, val as u32);
    }
}

/// MANAGE_PAGES Input Layout
pub struct ManagePagesInputLayout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> ManagePagesInputLayout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }
    pub fn set_function_id(&mut self, val: u16) {
        set_bits_u32(self.data, 80, 16, val as u32);
    }
    pub fn set_input_num_entries(&mut self, val: u32) {
        set_bits_u32(self.data, 96, 32, val);
    }
}

/// QUERY_PAGES Output Layout
pub struct QueryPagesOutputLayout<'a> {
    pub(crate) data: &'a [u8],
}

impl<'a> QueryPagesOutputLayout<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
    pub fn function_id(&self) -> u16 {
        get_bits_u32(self.data, 80, 16) as u16
    }
    pub fn num_pages(&self) -> u32 {
        get_bits_u32(self.data, 96, 32)
    }
}

/// QUERY_HCA_CAP Input Layout
pub struct QueryHcaCapInputLayout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> QueryHcaCapInputLayout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }
    pub fn set_op_mod(&mut self, val: u16) {
        set_bits_u32(self.data, 48, 16, val as u32);
    }
    pub fn set_ec_vf_function(&mut self, val: bool) {
        set_bits_u32(self.data, 65, 1, if val { 1 } else { 0 });
    }
}

/// QUERY_NIC_VPORT_CONTEXT Input Layout
pub struct QueryNicVportContextInputLayout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> QueryNicVportContextInputLayout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }
    pub fn set_other_vport(&mut self, val: bool) {
        set_bits_u32(self.data, 64, 1, if val { 1 } else { 0 });
    }
    pub fn set_vport_number(&mut self, val: u16) {
        set_bits_u32(self.data, 80, 16, val as u32);
    }
    pub fn set_allowed_list_type(&mut self, val: u8) {
        set_bits_u32(self.data, 101, 3, val as u32);
    }
}

/// QUERY_NIC_VPORT_CONTEXT Output Layout
pub struct QueryNicVportContextOutputLayout<'a> {
    pub(crate) data: &'a [u8],
}

impl<'a> QueryNicVportContextOutputLayout<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn min_wqe_inline_mode(&self) -> u8 {
        get_bits_u32(self.data, 133, 3) as u8
    }

    pub fn mtu(&self) -> u16 {
        get_bits_u32(self.data, 432, 16) as u16
    }
    pub fn allowed_list_size(&self) -> u16 {
        get_bits_u32(self.data, 2068, 12) as u16
    }

    pub fn permanent_address(&self) -> &'a [u8] {
        &self.data[0x104..0x10c]
    }

    pub fn current_uc_mac_address(&self, index: usize) -> Option<&'a [u8]> {
        let off = 0x110 + index * 8;
        self.data.get(off..off + 8)
    }
}

/// MODIFY_NIC_VPORT_CONTEXT Input Layout
pub struct ModifyNicVportContextInputLayout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> ModifyNicVportContextInputLayout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }

    pub fn set_other_vport(&mut self, val: bool) {
        set_bits_u32(self.data, 64, 1, if val { 1 } else { 0 });
    }
    pub fn set_vport_number(&mut self, val: u16) {
        set_bits_u32(self.data, 80, 16, val as u32);
    }
    pub fn set_field_select_mtu(&mut self, val: bool) {
        set_bits_u32(self.data, 121, 1, if val { 1 } else { 0 });
    }
    pub fn set_field_select_permanent_address(&mut self, val: bool) {
        set_bits_u32(self.data, 124, 1, if val { 1 } else { 0 });
    }

    pub fn set_mtu(&mut self, val: u16) {
        set_bits_u32(self.data, 2352, 16, val as u32);
    }

    pub fn permanent_address_mut(&mut self) -> &mut [u8] {
        &mut self.data[0x1f4..0x1fc]
    }
}

/// QUERY_VPORT_STATE Input Layout
pub struct QueryVportStateInputLayout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> QueryVportStateInputLayout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }
    pub fn set_op_mod(&mut self, val: u16) {
        set_bits_u32(self.data, 48, 16, val as u32);
    }
    pub fn set_other_vport(&mut self, val: bool) {
        set_bits_u32(self.data, 64, 1, if val { 1 } else { 0 });
    }
    pub fn set_vport_number(&mut self, val: u16) {
        set_bits_u32(self.data, 80, 16, val as u32);
    }
}

/// QUERY_VPORT_STATE Output Layout
pub struct QueryVportStateOutputLayout<'a> {
    pub(crate) data: &'a [u8],
}

impl<'a> QueryVportStateOutputLayout<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
    pub fn max_tx_speed(&self) -> u16 {
        get_bits_u32(self.data, 96, 16) as u16
    }
    pub fn admin_state(&self) -> u8 {
        get_bits_u32(self.data, 120, 4) as u8
    }
    pub fn state(&self) -> u8 {
        get_bits_u32(self.data, 124, 4) as u8
    }
}

/// QUERY_VNIC_ENV Input Layout
pub struct QueryVnicEnvInputLayout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> QueryVnicEnvInputLayout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }
    pub fn set_op_mod(&mut self, val: u16) {
        set_bits_u32(self.data, 48, 16, val as u32);
    }
    pub fn set_other_vport(&mut self, val: bool) {
        set_bits_u32(self.data, 64, 1, if val { 1 } else { 0 });
    }
    pub fn set_vport_number(&mut self, val: u16) {
        set_bits_u32(self.data, 80, 16, val as u32);
    }
}

/// QUERY_VNIC_ENV Output Layout
pub struct QueryVnicEnvOutputLayout<'a> {
    pub(crate) data: &'a [u8],
}

impl<'a> QueryVnicEnvOutputLayout<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn receive_discard_vport_down(&self) -> u64 {
        get_bits_u64(self.data, 320)
    }

    pub fn transmit_discard_vport_down(&self) -> u64 {
        get_bits_u64(self.data, 384)
    }
}

/// MODIFY_VPORT_STATE Input Layout
pub struct ModifyVportStateInputLayout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> ModifyVportStateInputLayout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }
    pub fn set_op_mod(&mut self, val: u16) {
        set_bits_u32(self.data, 48, 16, val as u32);
    }
    pub fn set_other_vport(&mut self, val: bool) {
        set_bits_u32(self.data, 64, 1, if val { 1 } else { 0 });
    }
    pub fn set_vport_number(&mut self, val: u16) {
        set_bits_u32(self.data, 80, 16, val as u32);
    }
    pub fn set_admin_state(&mut self, val: u8) {
        set_bits_u32(self.data, 120, 4, val as u32);
    }
}

/// QUERY_VHCA_STATE Input Layout
pub struct QueryVhcaStateInputLayout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> QueryVhcaStateInputLayout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }
    pub fn set_uid(&mut self, val: u16) {
        set_bits_u32(self.data, 16, 16, val as u32);
    }
    pub fn set_op_mod(&mut self, val: u16) {
        set_bits_u32(self.data, 48, 16, val as u32);
    }
    pub fn set_embedded_cpu_function(&mut self, val: bool) {
        set_bits_u32(self.data, 64, 1, if val { 1 } else { 0 });
    }
    pub fn set_function_id(&mut self, val: u16) {
        set_bits_u32(self.data, 80, 16, val as u32);
    }
}

/// QUERY_VHCA_STATE Output Layout
pub struct QueryVhcaStateOutputLayout<'a> {
    pub(crate) data: &'a [u8],
}

impl<'a> QueryVhcaStateOutputLayout<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn arm_change_event(&self) -> bool {
        get_bits_u32(self.data, 128, 1) != 0
    }

    pub fn vhca_state(&self) -> u8 {
        get_bits_u32(self.data, 140, 4) as u8
    }

    pub fn sw_function_id(&self) -> u32 {
        get_bits_u32(self.data, 160, 32)
    }
}

/// MODIFY_VHCA_STATE Input Layout
pub struct ModifyVhcaStateInputLayout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> ModifyVhcaStateInputLayout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }
    pub fn set_uid(&mut self, val: u16) {
        set_bits_u32(self.data, 16, 16, val as u32);
    }
    pub fn set_op_mod(&mut self, val: u16) {
        set_bits_u32(self.data, 48, 16, val as u32);
    }
    pub fn set_embedded_cpu_function(&mut self, val: bool) {
        set_bits_u32(self.data, 64, 1, if val { 1 } else { 0 });
    }
    pub fn set_function_id(&mut self, val: u16) {
        set_bits_u32(self.data, 80, 16, val as u32);
    }
    pub fn set_field_select_sw_function_id(&mut self, val: bool) {
        set_bits_u32(self.data, 126, 1, if val { 1 } else { 0 });
    }
    pub fn set_field_select_arm_change_event(&mut self, val: bool) {
        set_bits_u32(self.data, 127, 1, if val { 1 } else { 0 });
    }
    pub fn set_arm_change_event(&mut self, val: bool) {
        set_bits_u32(self.data, 128, 1, if val { 1 } else { 0 });
    }
    pub fn set_vhca_state(&mut self, val: u8) {
        set_bits_u32(self.data, 140, 4, val as u32);
    }
    pub fn set_sw_function_id(&mut self, val: u32) {
        set_bits_u32(self.data, 160, 32, val);
    }
}

/// QUERY_VPORT_COUNTER Input Layout
pub struct QueryVportCounterInputLayout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> QueryVportCounterInputLayout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }
    pub fn set_op_mod(&mut self, val: u16) {
        set_bits_u32(self.data, 48, 16, val as u32);
    }
    pub fn set_other_vport(&mut self, val: bool) {
        set_bits_u32(self.data, 64, 1, if val { 1 } else { 0 });
    }
    pub fn set_port_num(&mut self, val: u8) {
        set_bits_u32(self.data, 76, 4, val as u32);
    }
    pub fn set_vport_number(&mut self, val: u16) {
        set_bits_u32(self.data, 80, 16, val as u32);
    }
    pub fn set_clear(&mut self, val: bool) {
        set_bits_u32(self.data, 192, 1, if val { 1 } else { 0 });
    }
}

/// FTE Match Set Layer 2-4 Layout
pub struct FteMatchSetLyr24Layout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> FteMatchSetLyr24Layout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }

    pub fn dmac_mut(&mut self) -> &mut [u8] {
        &mut self.data[0x00..0x06]
    }
    pub fn smac_mut(&mut self) -> &mut [u8] {
        &mut self.data[0x08..0x0e]
    }
    pub fn set_ethertype(&mut self, val: u16) {
        set_bits_u32(self.data, 64, 16, val as u32);
    }
    pub fn set_ip_protocol(&mut self, val: u8) {
        set_bits_u32(self.data, 80, 8, val as u32);
    }
    pub fn src_ipv4_mut(&mut self) -> &mut [u8] {
        &mut self.data[0x10..0x14]
    }
    pub fn dst_ipv4_mut(&mut self) -> &mut [u8] {
        &mut self.data[0x14..0x18]
    }
    pub fn src_ipv6_mut(&mut self) -> &mut [u8] {
        &mut self.data[0x20..0x30]
    }
    pub fn dst_ipv6_mut(&mut self) -> &mut [u8] {
        &mut self.data[0x30..0x40]
    }
    pub fn set_src_port(&mut self, val: u16) {
        set_bits_u32(self.data, 512, 16, val as u32);
    }
    pub fn set_dst_port(&mut self, val: u16) {
        set_bits_u32(self.data, 528, 16, val as u32);
    }
}
