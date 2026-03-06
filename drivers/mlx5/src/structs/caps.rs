// ============================================================================
// drivers/mlx5/src/structs/caps.rs - HCA Capabilities Layout
// ============================================================================

use crate::structs::get_bits_u32;

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
    pub fn vhc_id(&self) -> u32 {
        get_bits_u32(self.data, 0, 16)
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
    } // Same as QP? Check Linux ifc.
    // In Linux ifc: dword 4 has log_max_cq[8] at bit 8. (bit 136 total)
    // dword 4: log_max_srq_sz[8], log_max_qp_sz[8], log_max_cq_sz[8], log_max_mkey_sz[8]
    // Wait, let's look at the offsets I saw in caps.rs:
    // caps.max_cq = 1 << out_mbox.read_be8(0x11); => byte 0x11 = 17 bytes = 136 bits. Correct.
    // caps.max_sq = 1 << out_mbox.read_be8(0x13); => byte 0x13 = 19 bytes = 152 bits. Correct.
    // caps.max_rq = 1 << out_mbox.read_be8(0x14); => byte 0x14 = 20 bytes = 160 bits. Correct.

    pub fn log_max_mkey(&self) -> u32 {
        get_bits_u32(self.data, 192, 8)
    }

    pub fn num_ports(&self) -> u32 {
        get_bits_u32(self.data, 232, 8)
    }

    pub fn max_mtu(&self) -> u32 {
        get_bits_u32(self.data, 272, 16)
    }

    pub fn log_max_eq(&self) -> u32 {
        get_bits_u32(self.data, 120, 8)
    }
    pub fn log_max_rq(&self) -> u32 {
        get_bits_u32(self.data, 160, 8)
    }

    // Flags
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
}
