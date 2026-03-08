// ============================================================================
// drivers/mlx5/src/structs/queues.rs - Queue Context Layouts
// ============================================================================

use crate::structs::{set_bits_u32, set_bits_u64};

/// EQ Context Layout
pub struct EqContextLayout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> EqContextLayout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }

    // st: bit 20-23 (dword 0)
    pub fn set_state(&mut self, val: u8) {
        set_bits_u32(self.data, 20, 4, val as u32);
    }
    // log_eq_size: bit 99-103 (dword 3)
    pub fn set_log_eq_size(&mut self, val: u8) {
        set_bits_u32(self.data, 99, 5, val as u32);
    }
    // page_offset: bit 84-89 (dword 2)
    pub fn set_page_offset(&mut self, val: u8) {
        set_bits_u32(self.data, 84, 6, val as u32);
    }
    // uar_page: bit 104-127 (dword 3)
    pub fn set_uar_page(&mut self, val: u32) {
        set_bits_u32(self.data, 104, 24, val);
    }
    // intr: bit 180-191 (dword 5)
    pub fn set_intr(&mut self, val: u32) {
        set_bits_u32(self.data, 180, 12, val);
    }
    // log_page_size: bit 195-199 (dword 6)
    pub fn set_log_page_size(&mut self, val: u8) {
        set_bits_u32(self.data, 195, 5, val as u32);
    }
    // event_bitmask: bit 576-639 (byte 0x48 in context, absolute 0x58)
    pub fn set_event_bitmask(&mut self, val: u64) {
        set_bits_u64(self.data, 576, val);
    }
}

/// CQ Context Layout
pub struct CqContextLayout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> CqContextLayout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }

    // st: bit 20-23 (dword 0)
    pub fn set_state(&mut self, val: u8) {
        set_bits_u32(self.data, 20, 4, val as u32);
    }
    // cqe_comp_en: bit 17 (dword 0)
    pub fn set_cqe_comp_en(&mut self, val: bool) {
        set_bits_u32(self.data, 17, 1, if val { 1 } else { 0 });
    }
    // log_cq_size: bit 99-103 (dword 3)
    pub fn set_log_cq_size(&mut self, val: u8) {
        set_bits_u32(self.data, 99, 5, val as u32);
    }
    // page_offset: bit 84-89 (dword 2)
    pub fn set_page_offset(&mut self, val: u8) {
        set_bits_u32(self.data, 84, 6, val as u32);
    }
    // uar_page: bit 104-127 (dword 3)
    pub fn set_uar_page(&mut self, val: u32) {
        set_bits_u32(self.data, 104, 24, val);
    }
    // c_eqn: bit 160-191 (dword 5)
    pub fn set_c_eqn(&mut self, val: u32) {
        set_bits_u32(self.data, 160, 32, val);
    }
    // dbr_addr: bit 448-511 (dword 14-15)
    pub fn set_dbr_addr(&mut self, val: u64) {
        set_bits_u64(self.data, 448, val);
    }
    // log_page_size: bit 195-199 (dword 6)
    pub fn set_log_page_size(&mut self, val: u8) {
        set_bits_u32(self.data, 195, 5, val as u32);
    }
}

/// WQ (Work Queue) Layout (Used in SQ and RQ)
pub struct WqLayout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> WqLayout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }

    pub fn set_wq_type(&mut self, val: u8) {
        set_bits_u32(self.data, 0, 4, val as u32);
    }
    pub fn set_pd(&mut self, val: u32) {
        set_bits_u32(self.data, 72, 24, val);
    }
    pub fn set_uar_page(&mut self, val: u32) {
        set_bits_u32(self.data, 104, 24, val);
    }
    pub fn set_dbr_addr(&mut self, val: u64) {
        set_bits_u64(self.data, 128, val);
    }
    pub fn set_log_wq_stride(&mut self, val: u8) {
        set_bits_u32(self.data, 268, 4, val as u32);
    }
    pub fn set_log_wq_pg_sz(&mut self, val: u8) {
        set_bits_u32(self.data, 275, 5, val as u32);
    }
    pub fn set_log_wq_sz(&mut self, val: u8) {
        set_bits_u32(self.data, 283, 5, val as u32);
    }
}

/// SQ Context Layout
pub struct SqContextLayout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> SqContextLayout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }

    pub fn set_state(&mut self, val: u8) {
        set_bits_u32(self.data, 4, 4, val as u32);
    }
    pub fn set_flush_in_error_en(&mut self, val: bool) {
        set_bits_u32(self.data, 0, 1, if val { 1 } else { 0 });
    }
    pub fn set_mem_sq_type(&mut self, val: u8) {
        set_bits_u32(self.data, 7, 1, val as u32);
    }
    pub fn set_cqn(&mut self, val: u32) {
        set_bits_u32(self.data, 72, 24, val);
    }
    pub fn set_tis_lst_sz(&mut self, val: u16) {
        set_bits_u32(self.data, 256, 16, val as u32);
    }
    pub fn set_tis_num_0(&mut self, val: u32) {
        set_bits_u32(self.data, 360, 24, val);
    }

    pub fn wq(&mut self) -> WqLayout<'_> {
        WqLayout::new(&mut self.data[0x30..])
    }
}

/// RQ Context Layout
pub struct RqContextLayout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> RqContextLayout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }

    pub fn set_state(&mut self, val: u8) {
        set_bits_u32(self.data, 4, 4, val as u32);
    }
    pub fn set_cqn(&mut self, val: u32) {
        set_bits_u32(self.data, 72, 24, val);
    }
    pub fn set_scatter_fcs(&mut self, val: bool) {
        set_bits_u32(self.data, 1, 1, if val { 1 } else { 0 });
    }
    pub fn set_vlan_strip(&mut self, val: bool) {
        set_bits_u32(self.data, 0, 1, if val { 1 } else { 0 });
    }

    pub fn wq(&mut self) -> WqLayout<'_> {
        WqLayout::new(&mut self.data[0x30..])
    }
}
