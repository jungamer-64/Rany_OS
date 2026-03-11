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

    pub fn abs_native_port_num(&self) -> bool {
        get_bits_u32(self.data, 7, 1) != 0
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

    pub fn release_all_pages(&self) -> bool {
        get_bits_u32(self.data, 325, 1) != 0
    }

    pub fn max_sgl_for_optimized_performance(&self) -> u32 {
        get_bits_u32(self.data, 192, 8)
    }

    pub fn relaxed_ordering_write(&self) -> bool {
        get_bits_u32(self.data, 232, 1) != 0
    }

    pub fn relaxed_ordering_read_pci_enabled(&self) -> bool {
        get_bits_u32(self.data, 233, 1) != 0
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

    pub fn relaxed_ordering_read(&self) -> bool {
        get_bits_u32(self.data, 810, 1) != 0
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

    pub fn roce(&self) -> bool {
        get_bits_u32(self.data, 541, 1) != 0
    }

    pub fn atomic(&self) -> bool {
        get_bits_u32(self.data, 542, 1) != 0
    }

    pub fn pg(&self) -> bool {
        get_bits_u32(self.data, 551, 1) != 0
    }

    pub fn port_selection_cap(&self) -> bool {
        get_bits_u32(self.data, 592, 1) != 0
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

    pub fn roce_rw_supported(&self) -> bool {
        get_bits_u32(self.data, 929, 1) != 0
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

    pub fn set_abs_native_port_num(&mut self, val: bool) {
        set_bits_u32(self.data, 7, 1, if val { 1 } else { 0 });
    }

    pub fn set_release_all_pages(&mut self, val: bool) {
        set_bits_u32(self.data, 325, 1, if val { 1 } else { 0 });
    }

    pub fn set_roce(&mut self, val: bool) {
        set_bits_u32(self.data, 541, 1, if val { 1 } else { 0 });
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

pub struct EthOffloadsCapLayout<'a> {
    data: &'a [u8],
}

impl<'a> EthOffloadsCapLayout<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn csum_cap(&self) -> bool {
        get_bits_u32(self.data, 0, 1) != 0
    }

    pub fn lro_cap(&self) -> bool {
        get_bits_u32(self.data, 2, 1) != 0
    }

    pub fn rss_ind_tbl_cap(&self) -> u8 {
        get_bits_u32(self.data, 20, 4) as u8
    }

    pub fn wqe_inline_mode(&self) -> u8 {
        get_bits_u32(self.data, 18, 2) as u8
    }

    pub fn reg_umr_sq(&self) -> bool {
        get_bits_u32(self.data, 24, 1) != 0
    }
}

pub struct AtomicCapLayout<'a> {
    data: &'a [u8],
}

impl<'a> AtomicCapLayout<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn atomic_req_8b_endianness_mode(&self) -> u8 {
        get_bits_u32(self.data, 64, 2) as u8
    }

    pub fn supported_atomic_req_8b_endianness_mode_1(&self) -> bool {
        get_bits_u32(self.data, 70, 1) != 0
    }
}

pub struct AtomicCapLayoutMut<'a> {
    data: &'a mut [u8],
}

impl<'a> AtomicCapLayoutMut<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }

    pub fn set_atomic_req_8b_endianness_mode(&mut self, val: u8) {
        set_bits_u32(self.data, 64, 2, val as u32);
    }
}

const ODP_MEMORY_SCHEME_BASE: usize = 512;
const ODP_SCHEME_PAGE_PREFETCH_BIT: usize = 69;
const ODP_SCHEME_RC_CAPS_BASE: usize = 128;
const ODP_SCHEME_UD_CAPS_BASE: usize = 192;
const ODP_SCHEME_XRC_CAPS_BASE: usize = 224;
const ODP_SCHEME_DC_CAPS_BASE: usize = 256;
const ODP_CAP_SEND_BIT: usize = 0;
const ODP_CAP_RECEIVE_BIT: usize = 1;
const ODP_CAP_WRITE_BIT: usize = 2;
const ODP_CAP_READ_BIT: usize = 3;
const ODP_CAP_ATOMIC_BIT: usize = 4;
const ODP_CAP_SRQ_RECEIVE_BIT: usize = 5;
const ODP_MEM_PAGE_FAULT_BIT: usize = 1536;

fn odp_bit(data: &[u8], base: usize, bit: usize) -> bool {
    get_bits_u32(data, base + bit, 1) != 0
}

fn set_odp_bit(data: &mut [u8], base: usize, bit: usize, val: bool) {
    set_bits_u32(data, base + bit, 1, if val { 1 } else { 0 });
}

pub struct OdpCapLayout<'a> {
    data: &'a [u8],
}

impl<'a> OdpCapLayout<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn mem_page_fault(&self) -> bool {
        get_bits_u32(self.data, ODP_MEM_PAGE_FAULT_BIT, 1) != 0
    }

    pub fn memory_page_fault_page_prefetch(&self) -> bool {
        odp_bit(
            self.data,
            ODP_MEMORY_SCHEME_BASE,
            ODP_SCHEME_PAGE_PREFETCH_BIT,
        )
    }

    pub fn transport_ud_srq_receive(&self) -> bool {
        odp_bit(self.data, ODP_SCHEME_UD_CAPS_BASE, ODP_CAP_SRQ_RECEIVE_BIT)
    }

    pub fn transport_rc_srq_receive(&self) -> bool {
        odp_bit(self.data, ODP_SCHEME_RC_CAPS_BASE, ODP_CAP_SRQ_RECEIVE_BIT)
    }

    pub fn transport_xrc_send(&self) -> bool {
        odp_bit(self.data, ODP_SCHEME_XRC_CAPS_BASE, ODP_CAP_SEND_BIT)
    }

    pub fn transport_xrc_receive(&self) -> bool {
        odp_bit(self.data, ODP_SCHEME_XRC_CAPS_BASE, ODP_CAP_RECEIVE_BIT)
    }

    pub fn transport_xrc_write(&self) -> bool {
        odp_bit(self.data, ODP_SCHEME_XRC_CAPS_BASE, ODP_CAP_WRITE_BIT)
    }

    pub fn transport_xrc_read(&self) -> bool {
        odp_bit(self.data, ODP_SCHEME_XRC_CAPS_BASE, ODP_CAP_READ_BIT)
    }

    pub fn transport_xrc_atomic(&self) -> bool {
        odp_bit(self.data, ODP_SCHEME_XRC_CAPS_BASE, ODP_CAP_ATOMIC_BIT)
    }

    pub fn transport_xrc_srq_receive(&self) -> bool {
        odp_bit(self.data, ODP_SCHEME_XRC_CAPS_BASE, ODP_CAP_SRQ_RECEIVE_BIT)
    }

    pub fn transport_dc_send(&self) -> bool {
        odp_bit(self.data, ODP_SCHEME_DC_CAPS_BASE, ODP_CAP_SEND_BIT)
    }

    pub fn transport_dc_receive(&self) -> bool {
        odp_bit(self.data, ODP_SCHEME_DC_CAPS_BASE, ODP_CAP_RECEIVE_BIT)
    }

    pub fn transport_dc_write(&self) -> bool {
        odp_bit(self.data, ODP_SCHEME_DC_CAPS_BASE, ODP_CAP_WRITE_BIT)
    }

    pub fn transport_dc_read(&self) -> bool {
        odp_bit(self.data, ODP_SCHEME_DC_CAPS_BASE, ODP_CAP_READ_BIT)
    }

    pub fn transport_dc_atomic(&self) -> bool {
        odp_bit(self.data, ODP_SCHEME_DC_CAPS_BASE, ODP_CAP_ATOMIC_BIT)
    }

    pub fn transport_dc_srq_receive(&self) -> bool {
        odp_bit(self.data, ODP_SCHEME_DC_CAPS_BASE, ODP_CAP_SRQ_RECEIVE_BIT)
    }
}

pub struct OdpCapLayoutMut<'a> {
    data: &'a mut [u8],
}

impl<'a> OdpCapLayoutMut<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }

    pub fn set_mem_page_fault(&mut self, val: bool) {
        set_bits_u32(
            self.data,
            ODP_MEM_PAGE_FAULT_BIT,
            1,
            if val { 1 } else { 0 },
        );
    }

    pub fn set_transport_ud_srq_receive(&mut self, val: bool) {
        set_odp_bit(
            self.data,
            ODP_SCHEME_UD_CAPS_BASE,
            ODP_CAP_SRQ_RECEIVE_BIT,
            val,
        );
    }

    pub fn set_transport_rc_srq_receive(&mut self, val: bool) {
        set_odp_bit(
            self.data,
            ODP_SCHEME_RC_CAPS_BASE,
            ODP_CAP_SRQ_RECEIVE_BIT,
            val,
        );
    }

    pub fn set_transport_xrc_send(&mut self, val: bool) {
        set_odp_bit(self.data, ODP_SCHEME_XRC_CAPS_BASE, ODP_CAP_SEND_BIT, val);
    }

    pub fn set_transport_xrc_receive(&mut self, val: bool) {
        set_odp_bit(
            self.data,
            ODP_SCHEME_XRC_CAPS_BASE,
            ODP_CAP_RECEIVE_BIT,
            val,
        );
    }

    pub fn set_transport_xrc_write(&mut self, val: bool) {
        set_odp_bit(self.data, ODP_SCHEME_XRC_CAPS_BASE, ODP_CAP_WRITE_BIT, val);
    }

    pub fn set_transport_xrc_read(&mut self, val: bool) {
        set_odp_bit(self.data, ODP_SCHEME_XRC_CAPS_BASE, ODP_CAP_READ_BIT, val);
    }

    pub fn set_transport_xrc_atomic(&mut self, val: bool) {
        set_odp_bit(self.data, ODP_SCHEME_XRC_CAPS_BASE, ODP_CAP_ATOMIC_BIT, val);
    }

    pub fn set_transport_xrc_srq_receive(&mut self, val: bool) {
        set_odp_bit(
            self.data,
            ODP_SCHEME_XRC_CAPS_BASE,
            ODP_CAP_SRQ_RECEIVE_BIT,
            val,
        );
    }

    pub fn set_transport_dc_send(&mut self, val: bool) {
        set_odp_bit(self.data, ODP_SCHEME_DC_CAPS_BASE, ODP_CAP_SEND_BIT, val);
    }

    pub fn set_transport_dc_receive(&mut self, val: bool) {
        set_odp_bit(self.data, ODP_SCHEME_DC_CAPS_BASE, ODP_CAP_RECEIVE_BIT, val);
    }

    pub fn set_transport_dc_write(&mut self, val: bool) {
        set_odp_bit(self.data, ODP_SCHEME_DC_CAPS_BASE, ODP_CAP_WRITE_BIT, val);
    }

    pub fn set_transport_dc_read(&mut self, val: bool) {
        set_odp_bit(self.data, ODP_SCHEME_DC_CAPS_BASE, ODP_CAP_READ_BIT, val);
    }

    pub fn set_transport_dc_atomic(&mut self, val: bool) {
        set_odp_bit(self.data, ODP_SCHEME_DC_CAPS_BASE, ODP_CAP_ATOMIC_BIT, val);
    }

    pub fn set_transport_dc_srq_receive(&mut self, val: bool) {
        set_odp_bit(
            self.data,
            ODP_SCHEME_DC_CAPS_BASE,
            ODP_CAP_SRQ_RECEIVE_BIT,
            val,
        );
    }
}

pub struct RoceCapLayout<'a> {
    data: &'a [u8],
}

impl<'a> RoceCapLayout<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn sw_r_roce_src_udp_port(&self) -> bool {
        get_bits_u32(self.data, 4, 1) != 0
    }

    pub fn qp_ooo_transmit_default(&self) -> bool {
        get_bits_u32(self.data, 8, 1) != 0
    }
}

pub struct RoceCapLayoutMut<'a> {
    data: &'a mut [u8],
}

impl<'a> RoceCapLayoutMut<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }

    pub fn set_sw_r_roce_src_udp_port(&mut self, val: bool) {
        set_bits_u32(self.data, 4, 1, if val { 1 } else { 0 });
    }

    pub fn set_qp_ooo_transmit_default(&mut self, val: bool) {
        set_bits_u32(self.data, 8, 1, if val { 1 } else { 0 });
    }
}

pub struct PortSelectionCapLayout<'a> {
    data: &'a [u8],
}

impl<'a> PortSelectionCapLayout<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn port_select_flow_table_bypass(&self) -> bool {
        get_bits_u32(self.data, 18, 1) != 0
    }
}

pub struct PortSelectionCapLayoutMut<'a> {
    data: &'a mut [u8],
}

impl<'a> PortSelectionCapLayoutMut<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }

    pub fn set_port_select_flow_table_bypass(&mut self, val: bool) {
        set_bits_u32(self.data, 18, 1, if val { 1 } else { 0 });
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
        set_bits_u32(&mut data, 232, 1, 1);
        set_bits_u32(&mut data, 233, 1, 1);
        set_bits_u32(&mut data, 219, 5, 0x1a);
        set_bits_u32(&mut data, 224, 8, 0x14);
        set_bits_u32(&mut data, 234, 6, 0x1b);
        set_bits_u32(&mut data, 252, 4, 0x6);
        set_bits_u32(&mut data, 257, 1, 1);
        set_bits_u32(&mut data, 266, 1, 1);
        set_bits_u32(&mut data, 325, 1, 1);
        set_bits_u32(&mut data, 416, 1, 1);
        set_bits_u32(&mut data, 423, 1, 1);
        set_bits_u32(&mut data, 440, 8, 2);
        set_bits_u32(&mut data, 540, 1, 1);
        set_bits_u32(&mut data, 541, 1, 1);
        set_bits_u32(&mut data, 542, 1, 1);
        set_bits_u32(&mut data, 551, 1, 1);
        set_bits_u32(&mut data, 592, 1, 1);
        set_bits_u32(&mut data, 867, 5, 0x11);
        set_bits_u32(&mut data, 875, 5, 0x12);
        set_bits_u32(&mut data, 810, 1, 1);
        set_bits_u32(&mut data, 929, 1, 1);
        set_bits_u32(&mut data, 1088, 2, 0x1);
        set_bits_u32(&mut data, 1090, 2, 0x2);
        set_bits_u32(&mut data, 1002, 1, 1);
        set_bits_u32(&mut data, 1168, 16, 0x10);
        set_bits_u32(&mut data, 1471, 1, 1);
        set_bits_u32(&mut data, 1552, 8, 3);
        set_bits_u32(&mut data, 1566, 1, 1);
        set_bits_u32(&mut data, 7, 1, 1);

        let view = HcaCapLayout::new(&data);
        assert!(view.hca_cap_2());
        assert!(view.abs_native_port_num());
        assert_eq!(view.vhca_id(), 0x1234);
        assert_eq!(view.log_max_qp_sz(), 0x18);
        assert_eq!(view.log_max_cq_sz(), 0x16);
        assert!(view.relaxed_ordering_write());
        assert!(view.relaxed_ordering_read_pci_enabled());
        assert_eq!(view.log_max_cq(), 0x1a);
        assert_eq!(view.log_max_eq_sz(), 0x14);
        assert_eq!(view.log_max_mkey(), 0x1b);
        assert_eq!(view.log_max_eq(), 0x6);
        assert!(view.driver_version());
        assert!(view.mkey_by_name());
        assert!(view.release_all_pages());
        assert!(view.vport_group_manager());
        assert!(view.eswitch_manager());
        assert_eq!(view.num_ports(), 2);
        assert!(view.eth_net_offloads());
        assert!(view.roce());
        assert!(view.atomic());
        assert!(view.pg());
        assert!(view.port_selection_cap());
        assert_eq!(view.log_max_rq(), 0x11);
        assert_eq!(view.log_max_sq(), 0x12);
        assert!(view.relaxed_ordering_read());
        assert!(view.roce_rw_supported());
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
            view.set_abs_native_port_num(true);
            view.set_release_all_pages(true);
            view.set_roce(true);
            view.set_vhca_state(true);
            view.set_event_on_vhca_state_teardown_request(true);
            view.set_event_on_vhca_state_in_use(true);
            view.set_event_on_vhca_state_active(true);
            view.set_event_on_vhca_state_allocated(true);
        }

        assert_eq!(get_bits_u32(&data, 528, 2), 0x2);
        assert_eq!(get_bits_u32(&data, 1168, 16), 0x10);
        assert_eq!(get_bits_u32(&data, 266, 1), 1);
        assert_eq!(get_bits_u32(&data, 7, 1), 1);
        assert_eq!(get_bits_u32(&data, 325, 1), 1);
        assert_eq!(get_bits_u32(&data, 541, 1), 1);
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

    #[test]
    fn roce_cap_layout_reads_and_writes_linux_ifc_offsets() {
        let mut data = [0u8; 256];
        set_bits_u32(&mut data, 4, 1, 1);
        set_bits_u32(&mut data, 8, 1, 1);

        let view = RoceCapLayout::new(&data);
        assert!(view.sw_r_roce_src_udp_port());
        assert!(view.qp_ooo_transmit_default());

        let mut data = [0u8; 256];
        {
            let mut view = RoceCapLayoutMut::new(&mut data);
            view.set_sw_r_roce_src_udp_port(true);
            view.set_qp_ooo_transmit_default(true);
        }

        assert_eq!(get_bits_u32(&data, 4, 1), 1);
        assert_eq!(get_bits_u32(&data, 8, 1), 1);
    }

    #[test]
    fn atomic_cap_layout_reads_and_writes_linux_ifc_offsets() {
        let mut data = [0u8; 256];
        set_bits_u32(&mut data, 64, 2, 0x1);
        set_bits_u32(&mut data, 70, 1, 1);

        let view = AtomicCapLayout::new(&data);
        assert_eq!(view.atomic_req_8b_endianness_mode(), 0x1);
        assert!(view.supported_atomic_req_8b_endianness_mode_1());

        let mut data = [0u8; 256];
        {
            let mut view = AtomicCapLayoutMut::new(&mut data);
            view.set_atomic_req_8b_endianness_mode(0x1);
        }

        assert_eq!(get_bits_u32(&data, 64, 2), 0x1);
    }

    #[test]
    fn eth_offloads_cap_layout_reads_linux_ifc_offsets() {
        let mut data = [0u8; 256];
        set_bits_u32(&mut data, 0, 1, 1);
        set_bits_u32(&mut data, 2, 1, 1);
        set_bits_u32(&mut data, 18, 2, 0x1);
        set_bits_u32(&mut data, 20, 4, 0x7);
        set_bits_u32(&mut data, 24, 1, 1);

        let view = EthOffloadsCapLayout::new(&data);
        assert!(view.csum_cap());
        assert!(view.lro_cap());
        assert_eq!(view.wqe_inline_mode(), 0x1);
        assert_eq!(view.rss_ind_tbl_cap(), 0x7);
        assert!(view.reg_umr_sq());
    }

    #[test]
    fn odp_cap_layout_reads_and_writes_linux_ifc_offsets() {
        let mut data = [0u8; 256];
        set_bits_u32(&mut data, 581, 1, 1);
        set_bits_u32(&mut data, 1536, 1, 1);
        set_bits_u32(&mut data, 133, 1, 1);
        set_bits_u32(&mut data, 197, 1, 1);
        set_bits_u32(&mut data, 224, 1, 1);
        set_bits_u32(&mut data, 225, 1, 1);
        set_bits_u32(&mut data, 226, 1, 1);
        set_bits_u32(&mut data, 227, 1, 1);
        set_bits_u32(&mut data, 228, 1, 1);
        set_bits_u32(&mut data, 229, 1, 1);
        set_bits_u32(&mut data, 256, 1, 1);
        set_bits_u32(&mut data, 257, 1, 1);
        set_bits_u32(&mut data, 258, 1, 1);
        set_bits_u32(&mut data, 259, 1, 1);
        set_bits_u32(&mut data, 260, 1, 1);
        set_bits_u32(&mut data, 261, 1, 1);

        let view = OdpCapLayout::new(&data);
        assert!(view.memory_page_fault_page_prefetch());
        assert!(view.mem_page_fault());
        assert!(view.transport_rc_srq_receive());
        assert!(view.transport_ud_srq_receive());
        assert!(view.transport_xrc_send());
        assert!(view.transport_xrc_receive());
        assert!(view.transport_xrc_write());
        assert!(view.transport_xrc_read());
        assert!(view.transport_xrc_atomic());
        assert!(view.transport_xrc_srq_receive());
        assert!(view.transport_dc_send());
        assert!(view.transport_dc_receive());
        assert!(view.transport_dc_write());
        assert!(view.transport_dc_read());
        assert!(view.transport_dc_atomic());
        assert!(view.transport_dc_srq_receive());

        let mut data = [0u8; 256];
        {
            let mut view = OdpCapLayoutMut::new(&mut data);
            view.set_mem_page_fault(true);
            view.set_transport_rc_srq_receive(true);
            view.set_transport_ud_srq_receive(true);
            view.set_transport_xrc_send(true);
            view.set_transport_xrc_receive(true);
            view.set_transport_xrc_write(true);
            view.set_transport_xrc_read(true);
            view.set_transport_xrc_atomic(true);
            view.set_transport_xrc_srq_receive(true);
            view.set_transport_dc_send(true);
            view.set_transport_dc_receive(true);
            view.set_transport_dc_write(true);
            view.set_transport_dc_read(true);
            view.set_transport_dc_atomic(true);
            view.set_transport_dc_srq_receive(true);
        }

        assert_eq!(get_bits_u32(&data, 1536, 1), 1);
        assert_eq!(get_bits_u32(&data, 133, 1), 1);
        assert_eq!(get_bits_u32(&data, 197, 1), 1);
        assert_eq!(get_bits_u32(&data, 224, 1), 1);
        assert_eq!(get_bits_u32(&data, 225, 1), 1);
        assert_eq!(get_bits_u32(&data, 226, 1), 1);
        assert_eq!(get_bits_u32(&data, 227, 1), 1);
        assert_eq!(get_bits_u32(&data, 228, 1), 1);
        assert_eq!(get_bits_u32(&data, 229, 1), 1);
        assert_eq!(get_bits_u32(&data, 256, 1), 1);
        assert_eq!(get_bits_u32(&data, 257, 1), 1);
        assert_eq!(get_bits_u32(&data, 258, 1), 1);
        assert_eq!(get_bits_u32(&data, 259, 1), 1);
        assert_eq!(get_bits_u32(&data, 260, 1), 1);
        assert_eq!(get_bits_u32(&data, 261, 1), 1);
    }

    #[test]
    fn port_selection_cap_layout_reads_and_writes_linux_ifc_offsets() {
        let mut data = [0u8; 256];
        set_bits_u32(&mut data, 18, 1, 1);

        let view = PortSelectionCapLayout::new(&data);
        assert!(view.port_select_flow_table_bypass());

        let mut data = [0u8; 256];
        {
            let mut view = PortSelectionCapLayoutMut::new(&mut data);
            view.set_port_select_flow_table_bypass(true);
        }

        assert_eq!(get_bits_u32(&data, 18, 1), 1);
    }
}
