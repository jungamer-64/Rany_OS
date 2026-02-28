use super::*;

impl VirtioNetDevice {
    /// MACアドレスを取得
    pub fn mac_address(&self) -> [u8; 6] {
        self.config.mac
    }
}
