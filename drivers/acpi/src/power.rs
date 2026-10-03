//! Fixed power register geometry decoded from the catalogued FADT.

use crate::{AcpiError, AcpiErrorKind, GenericAddress, GenericAddressSpace, RegisterAccessSize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedRegister {
    address: GenericAddress,
    bytes: u8,
}

impl FixedRegister {
    pub const fn address(self) -> GenericAddress {
        self.address
    }
    pub const fn bytes(self) -> u8 {
        self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerRegisterDescription {
    pub pm1a_event: Option<FixedRegister>,
    pub pm1b_event: Option<FixedRegister>,
    pub pm1a_control: Option<FixedRegister>,
    pub pm1b_control: Option<FixedRegister>,
    pub timer: Option<FixedRegister>,
    pub timer_32bit: bool,
    pub fixed_power_button: bool,
    pub fixed_sleep_button: bool,
    pub smi_enable: Option<(FixedRegister, u8)>,
    pub reset: Option<(FixedRegister, u8)>,
    pub sleep_control: Option<FixedRegister>,
    pub hardware_reduced: bool,
}

impl PowerRegisterDescription {
    pub fn ranges(&self) -> impl Iterator<Item = FixedRegister> + '_ {
        [
            self.pm1a_event,
            self.pm1b_event,
            self.pm1a_control,
            self.pm1b_control,
            self.timer,
            self.smi_enable.map(|pair| pair.0),
            self.reset.map(|pair| pair.0),
            self.sleep_control,
        ]
        .into_iter()
        .flatten()
    }
}

pub(crate) fn parse(bytes: &[u8]) -> Result<PowerRegisterDescription, AcpiError> {
    let flags = read32(bytes, 112)?;
    let hardware_reduced = flags & (1 << 20) != 0;
    let reset = if flags & (1 << 10) != 0 {
        Some((gas_register(bytes, 116, 1)?, byte(bytes, 128)?))
    } else {
        None
    };
    let mut result = PowerRegisterDescription {
        pm1a_event: None,
        pm1b_event: None,
        pm1a_control: None,
        pm1b_control: None,
        timer: None,
        timer_32bit: flags & (1 << 8) != 0,
        smi_enable: None,
        reset,
        sleep_control: None,
        hardware_reduced,
        fixed_power_button: !hardware_reduced && flags & (1 << 4) == 0,
        fixed_sleep_button: !hardware_reduced && flags & (1 << 5) == 0,
    };
    if hardware_reduced {
        result.sleep_control = Some(gas_register(bytes, 244, 1)?);
        return Ok(result);
    }
    let event_len = byte(bytes, 88)?;
    let control_len = byte(bytes, 89)?;
    let timer_len = byte(bytes, 91)?;
    if event_len != 0 && (event_len < 4 || !event_len.is_multiple_of(2)) {
        return Err(invalid(
            "PM1 event block must contain equal status and enable halves",
        ));
    }
    if control_len != 0 && control_len < 2 {
        return Err(invalid(
            "PM1 control block must contain its two-byte register",
        ));
    }
    if timer_len != 0 && timer_len < 4 {
        return Err(invalid(
            "PM timer block must contain its four-byte register",
        ));
    }
    result.pm1a_event = block(bytes, 56, 148, event_len, RegisterAccessSize::Word)?;
    result.pm1b_event = block(bytes, 60, 160, event_len, RegisterAccessSize::Word)?;
    result.pm1a_control = block(bytes, 64, 172, control_len, RegisterAccessSize::Word)?;
    result.pm1b_control = block(bytes, 68, 184, control_len, RegisterAccessSize::Word)?;
    result.timer = block(bytes, 76, 208, timer_len, RegisterAccessSize::Dword)?;
    let smi = read32(bytes, 48)?;
    let enable = byte(bytes, 52)?;
    if smi != 0 && enable != 0 {
        result.smi_enable = Some((
            io_register(u64::from(smi), 1, RegisterAccessSize::Byte)?,
            enable,
        ));
    }
    Ok(result)
}

fn block(
    bytes: &[u8],
    legacy: usize,
    extended: usize,
    length: u8,
    access: RegisterAccessSize,
) -> Result<Option<FixedRegister>, AcpiError> {
    if length == 0 {
        return Ok(None);
    }
    if let Some(gas) = bytes.get(extended..extended + 12) {
        let address = crate::tables::parse_generic_address(gas)?;
        if address.address != 0 {
            validate_gas(address, length)?;
            return Ok(Some(FixedRegister {
                address,
                bytes: length,
            }));
        }
    }
    let base = u64::from(read32(bytes, legacy)?);
    if base == 0 {
        return Ok(None);
    }
    io_register(base, length, access).map(Some)
}

fn gas_register(bytes: &[u8], offset: usize, length: u8) -> Result<FixedRegister, AcpiError> {
    let gas = bytes
        .get(offset..offset + 12)
        .ok_or_else(|| invalid("FADT fixed register is truncated"))?;
    let address = crate::tables::parse_generic_address(gas)?;
    if u16::from(address.bit_width) != u16::from(length) * 8 {
        return Err(invalid(
            "FADT reset and sleep control registers require a byte field",
        ));
    }
    validate_gas(address, length)?;
    Ok(FixedRegister {
        address,
        bytes: length,
    })
}

fn validate_gas(address: GenericAddress, length: u8) -> Result<(), AcpiError> {
    if address.address == 0
        || address.bit_offset != 0
        || (address.bit_width != 0 && u16::from(address.bit_width) != u16::from(length) * 8)
    {
        return Err(invalid("FADT fixed register width or offset is invalid"));
    }
    validate_span(address, length)
}

fn io_register(
    base: u64,
    length: u8,
    access_size: RegisterAccessSize,
) -> Result<FixedRegister, AcpiError> {
    let address = GenericAddress {
        address_space: GenericAddressSpace::SystemIo,
        bit_width: 0,
        bit_offset: 0,
        access_size,
        address: base,
    };
    validate_span(address, length)?;
    Ok(FixedRegister {
        address,
        bytes: length,
    })
}

fn validate_span(address: GenericAddress, length: u8) -> Result<(), AcpiError> {
    if length == 0 {
        return Err(invalid("FADT fixed register range is empty"));
    }
    let end = address
        .address
        .checked_add(u64::from(length))
        .ok_or_else(|| invalid("FADT fixed register range overflows"))?;
    if address.address_space == GenericAddressSpace::SystemIo && end > 0x1_0000 {
        return Err(invalid("FADT fixed register exceeds the x86 port domain"));
    }
    Ok(())
}

fn byte(bytes: &[u8], offset: usize) -> Result<u8, AcpiError> {
    bytes
        .get(offset)
        .copied()
        .ok_or_else(|| invalid("FADT power fields are truncated"))
}
fn read32(bytes: &[u8], offset: usize) -> Result<u32, AcpiError> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| invalid("FADT power fields are truncated"))?;
    Ok(u32::from_le_bytes(
        raw.try_into()
            .map_err(|_| invalid("FADT field width is invalid"))?,
    ))
}
fn invalid(detail: &'static str) -> AcpiError {
    AcpiError::table(AcpiErrorKind::InvalidEncoding, *b"FACP", detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fadt() -> [u8; 276] {
        let mut bytes = [0; 276];
        bytes[56..60].copy_from_slice(&0x600u32.to_le_bytes());
        bytes[64..68].copy_from_slice(&0x604u32.to_le_bytes());
        bytes[76..80].copy_from_slice(&0x608u32.to_le_bytes());
        bytes[88] = 4;
        bytes[89] = 2;
        bytes[91] = 4;
        bytes
    }
    #[test]
    fn legacy_optional_and_timer_width() {
        let bytes = fadt();
        let power = parse(&bytes).unwrap();
        assert_eq!(power.pm1a_control.unwrap().address().address, 0x604);
        assert!(power.pm1b_control.is_none());
        assert!(!power.timer_32bit);
        assert_eq!(power.timer.unwrap().bytes(), 4);
    }
    #[test]
    fn extended_gas_overrides_legacy_and_rejects_bad_extent() {
        let mut bytes = fadt();
        bytes[172] = 1;
        bytes[173] = 16;
        bytes[175] = 2;
        bytes[176..184].copy_from_slice(&0x1804u64.to_le_bytes());
        assert_eq!(
            parse(&bytes)
                .unwrap()
                .pm1a_control
                .unwrap()
                .address()
                .address,
            0x1804
        );
        bytes[176..184].copy_from_slice(&0xffffu64.to_le_bytes());
        assert!(parse(&bytes).is_err());
        bytes[176..184].copy_from_slice(&0x1804u64.to_le_bytes());
        bytes[174] = 1;
        assert!(parse(&bytes).is_err());
    }
    #[test]
    fn reduced_hardware_ignores_pm1_and_requires_sleep_control() {
        let mut bytes = fadt();
        bytes[114] = 0x10;
        bytes[89] = 9;
        bytes[244] = 1;
        bytes[245] = 8;
        bytes[247] = 1;
        bytes[248..256].copy_from_slice(&0x700u64.to_le_bytes());
        let power = parse(&bytes).unwrap();
        assert!(power.hardware_reduced);
        assert!(power.pm1a_control.is_none());
        assert!(power.sleep_control.is_some());
        assert!(parse(&bytes[..244]).is_err());
    }
    #[test]
    fn reset_flag_requires_complete_byte_register() {
        let mut bytes = fadt();
        bytes[113] = 4;
        bytes[116] = 1;
        bytes[117] = 8;
        bytes[119] = 1;
        bytes[120..128].copy_from_slice(&0xcf9u64.to_le_bytes());
        bytes[128] = 6;
        let (reset, value) = parse(&bytes).unwrap().reset.unwrap();
        assert_eq!(reset.address().address, 0xcf9);
        assert_eq!(value, 6);
        assert!(parse(&bytes[..128]).is_err());
    }
    #[test]
    fn fixed_register_boundaries_and_reset_width_are_checked() {
        let mut bytes = fadt();
        bytes[89] = 1;
        assert!(parse(&bytes).is_err());
        bytes[89] = 4;
        bytes[91] = 8;
        assert_eq!(parse(&bytes).unwrap().pm1a_control.unwrap().bytes(), 4);
        bytes[113] = 4;
        bytes[116] = 1;
        bytes[117] = 0;
        bytes[119] = 1;
        bytes[120..128].copy_from_slice(&0xcf9u64.to_le_bytes());
        assert!(parse(&bytes).is_err());
        bytes[117] = 8;
        bytes[120..128].copy_from_slice(&0xffffu64.to_le_bytes());
        assert!(parse(&bytes).is_ok());
        bytes[116] = 0;
        bytes[120..128].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(parse(&bytes).is_err());
    }
}
