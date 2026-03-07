// ============================================================================
// drivers/mlx5/src/structs/caps.rs - HCA Capabilities Layout
// ============================================================================

use crate::structs::{get_bits_u32, set_bits_u32};

/// HCA Capabilities (General) Layout
/// Based on mlx5_ifc_hca_cap_bits
pub struct HcaCapLayout<'a> {
    data: &'a [u8],
}

impl<'a> HcaCapLayout<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    // dword 0
    pub fn vhca_id(&self) -> u32 {
        get_bits_u32(self.data, 16, 16)
    }

    // dword 1
    pub fn cmdif_checksum(&self) -> u32 {
        get_bits_u32(self.data, 38, 2)
    }

    // dword 2
    pub fn log_uar_page_sz(&self) -> u32 {
        get_bits_u32(self.data, 80, 4)
    }

    // dword 4
    pub fn log_max_cq(&self) -> u32 {
        get_bits_u32(self.data, 136, 8)
    }

    // dword 5
    pub fn log_max_qp(&self) -> u32 {
        get_bits_u32(self.data, 152, 8)
    }
    pub fn log_max_sq(&self) -> u32 {
        get_bits_u32(self.data, 152, 8)
    }

    pub fn log_max_mkey(&self) -> u32 {
        get_bits_u32(self.data, 192, 8)
    }

    // dword 7
    pub fn pkey_table_size(&self) -> u32 {
        get_bits_u32(self.data, 224, 16)
    }
    pub fn num_ports(&self) -> u32 {
        get_bits_u32(self.data, 232, 8)
    }

    // dword 8
    pub fn max_mtu(&self) -> u32 {
        get_bits_u32(self.data, 272, 16)
    }

    // dword 3
    pub fn log_max_eq(&self) -> u32 {
        get_bits_u32(self.data, 120, 8)
    }
    // dword 5
    pub fn log_max_rq(&self) -> u32 {
        get_bits_u32(self.data, 160, 8)
    }

    // Flags (various dwords)
    pub fn csum_cap(&self) -> bool {
        get_bits_u32(self.data, 279, 1) != 0
    }
    pub fn cqe_compression(&self) -> bool {
        get_bits_u32(self.data, 284, 1) != 0
    }
    pub fn vport_group_manager(&self) -> bool {
        get_bits_u32(self.data, 305, 1) != 0
    }
    pub fn scatter_fcs(&self) -> bool {
        get_bits_u32(self.data, 308, 1) != 0
    }
    pub fn vlan_strip(&self) -> bool {
        get_bits_u32(self.data, 310, 1) != 0
    }
    pub fn eswitch_manager(&self) -> bool {
        get_bits_u32(self.data, 306, 1) != 0
    }
    pub fn num_vhca_ports(&self) -> u32 {
        get_bits_u32(self.data, 352, 16)
    }
}

pub struct HcaCapLayoutMut<'a> {
    data: &'a mut [u8],
}

impl<'a> HcaCapLayoutMut<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }

    pub fn set_pkey_table_size(&mut self, val: u32) {
        set_bits_u32(self.data, 224, 16, val);
    }

    pub fn set_log_uar_page_sz(&mut self, val: u32) {
        set_bits_u32(self.data, 80, 4, val);
    }

    pub fn set_cmdif_checksum(&mut self, val: u32) {
        set_bits_u32(self.data, 38, 2, val);
    }

    pub fn set_vport_group_manager(&mut self, val: bool) {
        set_bits_u32(self.data, 305, 1, if val { 1 } else { 0 });
    }

    pub fn set_eswitch_manager(&mut self, val: bool) {
        set_bits_u32(self.data, 306, 1, if val { 1 } else { 0 });
    }
}
