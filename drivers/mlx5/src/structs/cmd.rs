// ============================================================================
// drivers/mlx5/src/structs/cmd.rs - Command Mailbox Layouts
// ============================================================================

use crate::structs::{get_bits_u32, set_bits_u32, get_bits_u64, set_bits_u64};

/// MKEY Context Layout
pub struct MkeyContextLayout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> MkeyContextLayout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self { Self { data } }
    
    // access_flags: bit 0-7 (byte 0)
    pub fn set_access_flags(&mut self, val: u8) { set_bits_u32(self.data, 0, 8, val as u32); }
    // translations_octword_size: bit 24-31 (byte 3)
    pub fn set_translations_octword_size(&mut self, val: u32) { set_bits_u32(self.data, 24, 8, val); }
    // PD: bit 40-63 (byte 5-7)
    pub fn set_pd(&mut self, val: u32) { set_bits_u32(self.data, 40, 24, val); }
    // start_addr: bit 64-127
    pub fn set_start_addr(&mut self, val: u64) { set_bits_u64(self.data, 64, val); }
    // byte_count: bit 128-191
    pub fn set_len(&mut self, val: u64) { set_bits_u64(self.data, 128, val); }
    // log_page_size: bit 192 (DW6 MSB)
    pub fn set_log_page_size(&mut self, val: u32) { set_bits_u32(self.data, 192, 5, val); }
    // mkey_7_0: bit 224 (byte 28, DW7 MSB)
    pub fn set_mkey_7_0(&mut self, val: u8) { set_bits_u32(self.data, 224, 8, val as u32); }
}

/// TIS Context Layout
pub struct TisContextLayout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> TisContextLayout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self { Self { data } }
    
    // lag_tx_port_affinity: bits 4-7 (dword 0)
    pub fn set_lag_tx_port_affinity(&mut self, val: u8) { set_bits_u32(self.data, 4, 4, val as u32); }
    // prio: bits 12-15 (dword 0)
    pub fn set_prio(&mut self, val: u8) { set_bits_u32(self.data, 12, 4, val as u32); }
    // transport_domain: bit 72-95 (byte 9-11)
    pub fn set_transport_domain(&mut self, val: u32) { set_bits_u32(self.data, 72, 24, val); }
    // pd: bit 200-223 (byte 25-27)
    pub fn set_pd(&mut self, val: u32) { set_bits_u32(self.data, 200, 24, val); }
}

/// TIR Context Layout
pub struct TirContextLayout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> TirContextLayout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self { Self { data } }
    
    // disp_type: bits 0-3 (dword 0)
    pub fn set_disp_type(&mut self, val: u8) { set_bits_u32(self.data, 0, 4, val as u32); }
    // inline_rqn: bits 232-255 (dword 7)
    pub fn set_inline_rqn(&mut self, val: u32) { set_bits_u32(self.data, 232, 24, val); }
    // indirect_table: bits 264-287 (dword 8)
    pub fn set_indirect_table(&mut self, val: u32) { set_bits_u32(self.data, 264, 24, val); }
    // rx_hash_fn: bits 288-291 (dword 9)
    pub fn set_rx_hash_fn(&mut self, val: u8) { set_bits_u32(self.data, 288, 4, val as u32); }
    // transport_domain: bits 304-327 (dword 9)
    pub fn set_transport_domain(&mut self, val: u32) { set_bits_u32(self.data, 304, 24, val); }
}

/// ENABLE_HCA Input Layout
pub struct EnableHcaInputLayout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> EnableHcaInputLayout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self { Self { data } }
    pub fn set_function_id(&mut self, val: u16) { set_bits_u32(self.data, 80, 16, val as u32); }
}

/// INIT_HCA Input Layout
pub struct InitHcaInputLayout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> InitHcaInputLayout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self { Self { data } }
    pub fn set_sw_vhca_id(&mut self, val: u16) { set_bits_u32(self.data, 96, 16, val as u32); }
}

/// MANAGE_PAGES Input Layout
pub struct ManagePagesInputLayout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> ManagePagesInputLayout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self { Self { data } }
    pub fn set_function_id(&mut self, val: u16) { set_bits_u32(self.data, 80, 16, val as u32); }
    pub fn set_input_num_entries(&mut self, val: u32) { set_bits_u32(self.data, 96, 32, val); }
}

/// QUERY_PAGES Output Layout
pub struct QueryPagesOutputLayout<'a> {
    pub(crate) data: &'a [u8],
}

impl<'a> QueryPagesOutputLayout<'a> {
    pub fn new(data: &'a [u8]) -> Self { Self { data } }
    pub fn function_id(&self) -> u16 { get_bits_u32(self.data, 80, 16) as u16 }
    pub fn num_pages(&self) -> u32 { get_bits_u32(self.data, 96, 32) }
}

/// QUERY_HCA_CAP Input Layout
pub struct QueryHcaCapInputLayout<'a> {
    pub(crate) data: &'a mut [u8],
}

impl<'a> QueryHcaCapInputLayout<'a> {
    pub fn new(data: &'a mut [u8]) -> Self { Self { data } }
    pub fn set_op_mod(&mut self, val: u16) { set_bits_u32(self.data, 48, 16, val as u32); }
}
