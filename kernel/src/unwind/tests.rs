use super::*;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_uleb128() {
    let mut reader = MemoryReader::new(&[0x00]);
    assert_eq!(reader.read_uleb128().unwrap(), 0);

    let mut reader = MemoryReader::new(&[0x01]);
    assert_eq!(reader.read_uleb128().unwrap(), 1);

    let mut reader = MemoryReader::new(&[0x7F]);
    assert_eq!(reader.read_uleb128().unwrap(), 127);

    let mut reader = MemoryReader::new(&[0x80, 0x01]);
    assert_eq!(reader.read_uleb128().unwrap(), 128);

    let mut reader = MemoryReader::new(&[0xE5, 0x8E, 0x26]);
    assert_eq!(reader.read_uleb128().unwrap(), 624485);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_sleb128() {
    let mut reader = MemoryReader::new(&[0x00]);
    assert_eq!(reader.read_sleb128().unwrap(), 0);

    let mut reader = MemoryReader::new(&[0x01]);
    assert_eq!(reader.read_sleb128().unwrap(), 1);

    let mut reader = MemoryReader::new(&[0x7F]);
    assert_eq!(reader.read_sleb128().unwrap(), -1);

    let mut reader = MemoryReader::new(&[0x80, 0x7F]);
    assert_eq!(reader.read_sleb128().unwrap(), -128);
}
