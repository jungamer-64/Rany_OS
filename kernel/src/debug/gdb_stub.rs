//! Minimal GDB remote serial protocol stub.
//!
//! Supported packets: `? g G m M c s Z0 z0`

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GdbStubError {
    MalformedPacket,
    InvalidChecksum,
    InvalidHex,
    InvalidCommand,
    InvalidAddress,
    TargetError,
    Unsupported,
}

pub trait GdbTarget {
    fn stop_signal(&self) -> u8;
    fn read_registers(&self, out: &mut Vec<u8>);
    fn write_registers(&mut self, regs: &[u8]) -> Result<(), GdbStubError>;
    fn read_memory(&self, addr: u64, out: &mut [u8]) -> Result<(), GdbStubError>;
    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), GdbStubError>;
    fn continue_exec(&mut self);
    fn step_exec(&mut self);
    fn insert_sw_breakpoint(&mut self, _addr: u64, _kind: u8) -> Result<(), GdbStubError> {
        Err(GdbStubError::Unsupported)
    }
    fn remove_sw_breakpoint(&mut self, _addr: u64, _kind: u8) -> Result<(), GdbStubError> {
        Err(GdbStubError::Unsupported)
    }
}

pub struct GdbStub;

impl GdbStub {
    pub const fn new() -> Self {
        Self
    }

    /// Handle a decoded payload (without `$...#xx` framing).
    pub fn handle_payload<T: GdbTarget>(
        &self,
        payload: &str,
        target: &mut T,
    ) -> Result<Option<String>, GdbStubError> {
        if payload.is_empty() {
            return Ok(Some(String::new()));
        }

        let cmd = payload.as_bytes()[0];
        match cmd {
            b'?' => Ok(Some(format!("S{:02x}", target.stop_signal()))),
            b'g' => {
                let mut regs = Vec::new();
                target.read_registers(&mut regs);
                Ok(Some(encode_hex(&regs)))
            }
            b'G' => {
                let regs = decode_hex(&payload[1..])?;
                target.write_registers(&regs)?;
                Ok(Some(String::from("OK")))
            }
            b'm' => {
                let (addr, len) = parse_addr_len(&payload[1..])?;
                let mut data = alloc::vec![0u8; len];
                target.read_memory(addr, &mut data)?;
                Ok(Some(encode_hex(&data)))
            }
            b'M' => {
                let (addr, bytes) = parse_write_memory_payload(&payload[1..])?;
                target.write_memory(addr, &bytes)?;
                Ok(Some(String::from("OK")))
            }
            b'c' => {
                target.continue_exec();
                Ok(Some(format!("S{:02x}", target.stop_signal())))
            }
            b's' => {
                target.step_exec();
                Ok(Some(format!("S{:02x}", target.stop_signal())))
            }
            b'Z' => self.handle_breakpoint(true, &payload[1..], target),
            b'z' => self.handle_breakpoint(false, &payload[1..], target),
            _ => Ok(Some(String::new())),
        }
    }

    fn handle_breakpoint<T: GdbTarget>(
        &self,
        insert: bool,
        payload: &str,
        target: &mut T,
    ) -> Result<Option<String>, GdbStubError> {
        // Format: "0,ADDR,KIND"
        let mut parts = payload.split(',');
        let typ = parts.next().ok_or(GdbStubError::InvalidCommand)?;
        let addr = parts.next().ok_or(GdbStubError::InvalidCommand)?;
        let kind = parts.next().ok_or(GdbStubError::InvalidCommand)?;
        if typ != "0" {
            return Err(GdbStubError::Unsupported);
        }
        let addr = parse_hex_u64(addr).ok_or(GdbStubError::InvalidAddress)?;
        let kind = parse_hex_u64(kind).ok_or(GdbStubError::InvalidCommand)? as u8;
        if insert {
            target.insert_sw_breakpoint(addr, kind)?;
        } else {
            target.remove_sw_breakpoint(addr, kind)?;
        }
        Ok(Some(String::from("OK")))
    }
}

static GDB_STUB: spin::Once<GdbStub> = spin::Once::new();

pub fn init_gdb_stub() -> &'static GdbStub {
    GDB_STUB.call_once(GdbStub::new)
}

pub fn gdb_stub() -> Option<&'static GdbStub> {
    GDB_STUB.get()
}

/// Frame response payload as `$payload#checksum`.
pub fn frame_packet(payload: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.push(b'$');
    out.extend_from_slice(payload.as_bytes());
    out.push(b'#');
    let csum = checksum(payload.as_bytes());
    let mut hex = [0u8; 2];
    encode_hex_byte(csum, &mut hex);
    out.extend_from_slice(&hex);
    out
}

/// Parse and verify framed packet, returning payload text.
pub fn parse_packet(packet: &[u8]) -> Result<&str, GdbStubError> {
    if packet.len() < 4 || packet[0] != b'$' {
        return Err(GdbStubError::MalformedPacket);
    }
    let hash_idx = packet
        .iter()
        .position(|b| *b == b'#')
        .ok_or(GdbStubError::MalformedPacket)?;
    if hash_idx + 3 > packet.len() {
        return Err(GdbStubError::MalformedPacket);
    }
    let payload = &packet[1..hash_idx];
    let expected = parse_hex_byte(&packet[hash_idx + 1..hash_idx + 3])?;
    let actual = checksum(payload);
    if expected != actual {
        return Err(GdbStubError::InvalidChecksum);
    }
    core::str::from_utf8(payload).map_err(|_| GdbStubError::MalformedPacket)
}

#[inline]
fn checksum(payload: &[u8]) -> u8 {
    payload
        .iter()
        .fold(0u8, |acc, b| acc.wrapping_add(*b))
}

fn parse_addr_len(text: &str) -> Result<(u64, usize), GdbStubError> {
    let (addr, len) = text.split_once(',').ok_or(GdbStubError::InvalidCommand)?;
    let addr = parse_hex_u64(addr).ok_or(GdbStubError::InvalidAddress)?;
    let len = parse_hex_u64(len).ok_or(GdbStubError::InvalidCommand)? as usize;
    Ok((addr, len))
}

fn parse_write_memory_payload(text: &str) -> Result<(u64, Vec<u8>), GdbStubError> {
    let (head, data_hex) = text.split_once(':').ok_or(GdbStubError::InvalidCommand)?;
    let (addr, len) = parse_addr_len(head)?;
    let data = decode_hex(data_hex)?;
    if data.len() != len {
        return Err(GdbStubError::InvalidCommand);
    }
    Ok((addr, data))
}

fn parse_hex_u64(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut out = 0u64;
    for ch in s.as_bytes() {
        out = out.checked_mul(16)?;
        out = out.checked_add(hex_nibble(*ch)? as u64)?;
    }
    Some(out)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, GdbStubError> {
    if (hex.len() & 1) != 0 {
        return Err(GdbStubError::InvalidHex);
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i]).ok_or(GdbStubError::InvalidHex)?;
        let lo = hex_nibble(bytes[i + 1]).ok_or(GdbStubError::InvalidHex)?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

#[inline]
fn parse_hex_byte(bytes: &[u8]) -> Result<u8, GdbStubError> {
    if bytes.len() != 2 {
        return Err(GdbStubError::InvalidHex);
    }
    let hi = hex_nibble(bytes[0]).ok_or(GdbStubError::InvalidHex)?;
    let lo = hex_nibble(bytes[1]).ok_or(GdbStubError::InvalidHex)?;
    Ok((hi << 4) | lo)
}

#[inline]
fn encode_hex_byte(byte: u8, out: &mut [u8; 2]) {
    out[0] = to_hex_ascii(byte >> 4);
    out[1] = to_hex_ascii(byte & 0x0f);
}

#[inline]
fn hex_nibble(ch: u8) -> Option<u8> {
    match ch {
        b'0'..=b'9' => Some(ch - b'0'),
        b'a'..=b'f' => Some(ch - b'a' + 10),
        b'A'..=b'F' => Some(ch - b'A' + 10),
        _ => None,
    }
}

#[inline]
fn to_hex_ascii(v: u8) -> u8 {
    match v & 0x0f {
        0..=9 => b'0' + (v & 0x0f),
        _ => b'a' + ((v & 0x0f) - 10),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct DummyTarget {
        regs: Vec<u8>,
        mem: Vec<u8>,
        breaks: Vec<(u64, u8)>,
        stop: u8,
    }

    impl GdbTarget for DummyTarget {
        fn stop_signal(&self) -> u8 {
            self.stop
        }

        fn read_registers(&self, out: &mut Vec<u8>) {
            out.extend_from_slice(&self.regs);
        }

        fn write_registers(&mut self, regs: &[u8]) -> Result<(), GdbStubError> {
            self.regs.clear();
            self.regs.extend_from_slice(regs);
            Ok(())
        }

        fn read_memory(&self, addr: u64, out: &mut [u8]) -> Result<(), GdbStubError> {
            let start = addr as usize;
            let end = start.saturating_add(out.len());
            if end > self.mem.len() {
                return Err(GdbStubError::TargetError);
            }
            out.copy_from_slice(&self.mem[start..end]);
            Ok(())
        }

        fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), GdbStubError> {
            let start = addr as usize;
            let end = start.saturating_add(data.len());
            if end > self.mem.len() {
                return Err(GdbStubError::TargetError);
            }
            self.mem[start..end].copy_from_slice(data);
            Ok(())
        }

        fn continue_exec(&mut self) {}
        fn step_exec(&mut self) {}

        fn insert_sw_breakpoint(&mut self, addr: u64, kind: u8) -> Result<(), GdbStubError> {
            self.breaks.push((addr, kind));
            Ok(())
        }

        fn remove_sw_breakpoint(&mut self, addr: u64, kind: u8) -> Result<(), GdbStubError> {
            self.breaks.retain(|b| *b != (addr, kind));
            Ok(())
        }
    }

    #[test_case]
    fn gdb_memory_read_and_write() {
        let stub = GdbStub::new();
        let mut target = DummyTarget {
            mem: alloc::vec![0u8; 16],
            stop: 5,
            ..Default::default()
        };
        let r = stub
            .handle_payload("M0,4:01020304", &mut target)
            .expect("write ok");
        assert_eq!(r, Some(String::from("OK")));
        let r = stub.handle_payload("m0,4", &mut target).expect("read ok");
        assert_eq!(r, Some(String::from("01020304")));
    }

    #[test_case]
    fn gdb_packet_roundtrip() {
        let payload = "g";
        let framed = frame_packet(payload);
        let parsed = parse_packet(&framed).expect("packet parse");
        assert_eq!(parsed, payload);
    }
}
