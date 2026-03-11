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

    pub fn hca_cap_2(&self) -> bool {
        get_bits_u32(self.data, 32, 1) != 0
    }

    pub fn vhca_id(&self) -> u32 {
        get_bits_u32(self.data, 48, 16)
    }

    pub fn cmdif_checksum(&self) -> u32 {
        get_bits_u32(self.data, 528, 2)
    }

    pub fn vhca_state(&self) -> bool {
        get_bits_u32(self.data, 1002, 1) != 0
    }

    pub fn log_uar_page_sz(&self) -> u32 {
        get_bits_u32(self.data, 1168, 16)
    }

    pub fn log_max_qp_sz(&self) -> u32 {
        get_bits_u32(self.data, 136, 8)
    }

    pub fn driver_version(&self) -> bool {
        get_bits_u32(self.data, 257, 1) != 0
    }

    pub fn mkey_by_name(&self) -> bool {
        get_bits_u32(self.data, 266, 1) != 0
    }

    pub fn max_sgl_for_optimized_performance(&self) -> u32 {
        get_bits_u32(self.data, 192, 8)
    }

    pub fn log_max_cq_sz(&self) -> u32 {
        get_bits_u32(self.data, 200, 8)
    }

    pub fn log_max_cq(&self) -> u32 {
        get_bits_u32(self.data, 219, 5)
    }

    pub fn log_max_sq(&self) -> u32 {
        get_bits_u32(self.data, 875, 5)
    }

    pub fn log_max_tir(&self) -> u32 {
        get_bits_u32(self.data, 883, 5)
    }

    pub fn log_max_tis(&self) -> u32 {
        get_bits_u32(self.data, 891, 5)
    }

    pub fn log_max_tis_per_sq(&self) -> u32 {
        get_bits_u32(self.data, 923, 5)
    }

    pub fn log_max_transport_domain(&self) -> u32 {
        get_bits_u32(self.data, 803, 5)
    }

    pub fn sq_ts_format(&self) -> u32 {
        get_bits_u32(self.data, 1088, 2)
    }

    pub fn rq_ts_format(&self) -> u32 {
        get_bits_u32(self.data, 1090, 2)
    }

    pub fn log_max_eq_sz(&self) -> u32 {
        get_bits_u32(self.data, 224, 8)
    }

    pub fn log_max_mkey(&self) -> u32 {
        get_bits_u32(self.data, 234, 6)
    }

    pub fn pkey_table_size(&self) -> u32 {
        get_bits_u32(self.data, 400, 16)
    }

    pub fn num_ports(&self) -> u32 {
        get_bits_u32(self.data, 440, 8)
    }

    pub fn log_max_eq(&self) -> u32 {
        get_bits_u32(self.data, 252, 4)
    }

    pub fn log_max_rq(&self) -> u32 {
        get_bits_u32(self.data, 867, 5)
    }

    pub fn vport_group_manager(&self) -> bool {
        get_bits_u32(self.data, 416, 1) != 0
    }

    pub fn eswitch_manager(&self) -> bool {
        get_bits_u32(self.data, 423, 1) != 0
    }

    pub fn eth_net_offloads(&self) -> bool {
        get_bits_u32(self.data, 540, 1) != 0
    }

    pub fn cqe_compression(&self) -> bool {
        get_bits_u32(self.data, 1471, 1) != 0
    }

    pub fn sw_owner_id(&self) -> bool {
        get_bits_u32(self.data, 1566, 1) != 0
    }

    pub fn num_vhca_ports(&self) -> u32 {
        get_bits_u32(self.data, 1552, 8)
    }
}

pub struct HcaCapLayoutMut<'a> {
    data: &'a mut [u8],
}

impl<'a> HcaCapLayoutMut<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }

    pub fn pkey_table_size(&self) -> u32 {
        get_bits_u32(self.data, 400, 16)
    }

    pub fn cmdif_checksum(&self) -> u32 {
        get_bits_u32(self.data, 528, 2)
    }

    pub fn set_pkey_table_size(&mut self, val: u32) {
        set_bits_u32(self.data, 400, 16, val);
    }

    pub fn set_log_uar_page_sz(&mut self, val: u32) {
        set_bits_u32(self.data, 1168, 16, val);
    }

    pub fn set_cmdif_checksum(&mut self, val: u32) {
        set_bits_u32(self.data, 528, 2, val);
    }

    pub fn set_mkey_by_name(&mut self, val: bool) {
        set_bits_u32(self.data, 266, 1, if val { 1 } else { 0 });
    }

    pub fn set_vhca_state(&mut self, val: bool) {
        set_bits_u32(self.data, 1002, 1, if val { 1 } else { 0 });
    }

    pub fn set_event_on_vhca_state_teardown_request(&mut self, val: bool) {
        set_bits_u32(self.data, 35, 1, if val { 1 } else { 0 });
    }

    pub fn set_event_on_vhca_state_in_use(&mut self, val: bool) {
        set_bits_u32(self.data, 36, 1, if val { 1 } else { 0 });
    }

    pub fn set_event_on_vhca_state_active(&mut self, val: bool) {
        set_bits_u32(self.data, 37, 1, if val { 1 } else { 0 });
    }

    pub fn set_event_on_vhca_state_allocated(&mut self, val: bool) {
        set_bits_u32(self.data, 38, 1, if val { 1 } else { 0 });
    }
}

pub struct HcaCap2Layout<'a> {
    data: &'a [u8],
}

impl<'a> HcaCap2Layout<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn sw_vhca_id_valid(&self) -> bool {
        get_bits_u32(self.data, 545, 1) != 0
    }

    pub fn sw_vhca_id(&self) -> u32 {
        get_bits_u32(self.data, 546, 14)
    }
}

pub struct HcaCap2LayoutMut<'a> {
    data: &'a mut [u8],
}

impl<'a> HcaCap2LayoutMut<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }

    pub fn set_sw_vhca_id_valid(&mut self, val: bool) {
        set_bits_u32(self.data, 545, 1, if val { 1 } else { 0 });
    }

    pub fn set_sw_vhca_id(&mut self, val: u16) {
        set_bits_u32(self.data, 546, 14, val as u32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structs::{get_bits_u32, set_bits_u32};

    #[test]
    fn hca_cap_layout_reads_linux_ifc_offsets() {
        let mut data = [0u8; 256];
        set_bits_u32(&mut data, 32, 1, 1);
        set_bits_u32(&mut data, 48, 16, 0x1234);
        set_bits_u32(&mut data, 136, 8, 0x18);
        set_bits_u32(&mut data, 200, 8, 0x16);
        set_bits_u32(&mut data, 219, 5, 0x1a);
        set_bits_u32(&mut data, 224, 8, 0x14);
        set_bits_u32(&mut data, 234, 6, 0x1b);
        set_bits_u32(&mut data, 252, 4, 0x6);
        set_bits_u32(&mut data, 257, 1, 1);
        set_bits_u32(&mut data, 266, 1, 1);
        set_bits_u32(&mut data, 416, 1, 1);
        set_bits_u32(&mut data, 423, 1, 1);
        set_bits_u32(&mut data, 440, 8, 2);
        set_bits_u32(&mut data, 540, 1, 1);
        set_bits_u32(&mut data, 867, 5, 0x11);
        set_bits_u32(&mut data, 875, 5, 0x12);
        set_bits_u32(&mut data, 1088, 2, 0x1);
        set_bits_u32(&mut data, 1090, 2, 0x2);
        set_bits_u32(&mut data, 1002, 1, 1);
        set_bits_u32(&mut data, 1168, 16, 0x10);
        set_bits_u32(&mut data, 1471, 1, 1);
        set_bits_u32(&mut data, 1552, 8, 3);
        set_bits_u32(&mut data, 1566, 1, 1);

        let view = HcaCapLayout::new(&data);
        assert!(view.hca_cap_2());
        assert_eq!(view.vhca_id(), 0x1234);
        assert_eq!(view.log_max_qp_sz(), 0x18);
        assert_eq!(view.log_max_cq_sz(), 0x16);
        assert_eq!(view.log_max_cq(), 0x1a);
        assert_eq!(view.log_max_eq_sz(), 0x14);
        assert_eq!(view.log_max_mkey(), 0x1b);
        assert_eq!(view.log_max_eq(), 0x6);
        assert!(view.driver_version());
        assert!(view.mkey_by_name());
        assert!(view.vport_group_manager());
        assert!(view.eswitch_manager());
        assert_eq!(view.num_ports(), 2);
        assert!(view.eth_net_offloads());
        assert_eq!(view.log_max_rq(), 0x11);
        assert_eq!(view.log_max_sq(), 0x12);
        assert_eq!(view.sq_ts_format(), 0x1);
        assert_eq!(view.rq_ts_format(), 0x2);
        assert!(view.vhca_state());
        assert_eq!(view.log_uar_page_sz(), 0x10);
        assert!(view.cqe_compression());
        assert_eq!(view.num_vhca_ports(), 3);
        assert!(view.sw_owner_id());
    }

    #[test]
    fn hca_cap_layout_mut_writes_linux_ifc_offsets() {
        let mut data = [0u8; 256];
        {
            let mut view = HcaCapLayoutMut::new(&mut data);
            view.set_cmdif_checksum(0x2);
            view.set_log_uar_page_sz(0x10);
            view.set_mkey_by_name(true);
            view.set_vhca_state(true);
            view.set_event_on_vhca_state_teardown_request(true);
            view.set_event_on_vhca_state_in_use(true);
            view.set_event_on_vhca_state_active(true);
            view.set_event_on_vhca_state_allocated(true);
        }

        assert_eq!(get_bits_u32(&data, 528, 2), 0x2);
        assert_eq!(get_bits_u32(&data, 1168, 16), 0x10);
        assert_eq!(get_bits_u32(&data, 266, 1), 1);
        assert_eq!(get_bits_u32(&data, 1002, 1), 1);
        assert_eq!(get_bits_u32(&data, 35, 1), 1);
        assert_eq!(get_bits_u32(&data, 36, 1), 1);
        assert_eq!(get_bits_u32(&data, 37, 1), 1);
        assert_eq!(get_bits_u32(&data, 38, 1), 1);
    }

    #[test]
    fn hca_cap2_layout_reads_and_writes_linux_ifc_offsets() {
        let mut data = [0u8; 256];
        set_bits_u32(&mut data, 545, 1, 1);
        set_bits_u32(&mut data, 546, 14, 0x2aaa);

        let view = HcaCap2Layout::new(&data);
        assert!(view.sw_vhca_id_valid());
        assert_eq!(view.sw_vhca_id(), 0x2aaa);

        let mut data = [0u8; 256];
        {
            let mut view = HcaCap2LayoutMut::new(&mut data);
            view.set_sw_vhca_id_valid(true);
            view.set_sw_vhca_id(0x1555);
        }
        assert_eq!(get_bits_u32(&data, 545, 1), 1);
        assert_eq!(get_bits_u32(&data, 546, 14), 0x1555);
    }
}
