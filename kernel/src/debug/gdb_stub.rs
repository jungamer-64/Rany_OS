//! Minimal kernel GDB remote protocol stub.
//!
//! Supported packets: `? g G m M c s Z0 z0`
#![allow(dead_code)]
use crate::sync::PoisonLock;
use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use x86_64::structures::idt::InterruptStackFrame;

const ACTIVE_NONE: usize = usize::MAX;
const MAX_PACKET_BUFFER: usize = 8192;
const KERNEL_GDB_REG_BYTES: usize = 24 * 8;

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
    fn resume_run(&mut self);
    fn single_step_run(&mut self);
    fn insert_sw_breakpoint(&mut self, _addr: u64, _kind: u8) -> Result<(), GdbStubError> {
        Err(GdbStubError::Unsupported)
    }
    fn remove_sw_breakpoint(&mut self, _addr: u64, _kind: u8) -> Result<(), GdbStubError> {
        Err(GdbStubError::Unsupported)
    }
}

pub trait GdbTransport: Send + Sync {
    fn try_read_byte(&self) -> Option<u8>;
    fn write_bytes(&self, bytes: &[u8]);
}

struct KernelGdbTarget {
    regs: [u8; KERNEL_GDB_REG_BYTES],
    stop_signal: u8,
    resume_requested: bool,
    single_step: bool,
    breakpoints: Vec<(u64, u8)>,
}

impl Default for KernelGdbTarget {
    fn default() -> Self {
        Self {
            regs: [0u8; KERNEL_GDB_REG_BYTES],
            stop_signal: 0,
            resume_requested: false,
            single_step: false,
            breakpoints: Vec::new(),
        }
    }
}

impl KernelGdbTarget {
    fn set_u64_reg(&mut self, idx: usize, value: u64) {
        let off = idx.saturating_mul(8);
        if off + 8 > self.regs.len() {
            return;
        }
        self.regs[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn capture_trap(&mut self, signal: u8, frame: &InterruptStackFrame) {
        self.stop_signal = signal;
        self.resume_requested = false;
        self.single_step = false;
        self.regs.fill(0);

        // GDB x86_64 register order: rax..r15, rip, eflags, cs, ss, ds, es, fs, gs
        self.set_u64_reg(7, frame.stack_pointer.as_u64());
        self.set_u64_reg(16, frame.instruction_pointer.as_u64());
        self.set_u64_reg(17, frame.cpu_flags.bits());
        self.set_u64_reg(18, frame.code_segment.0 as u64);
        self.set_u64_reg(19, frame.stack_segment.0 as u64);
    }
}

impl GdbTarget for KernelGdbTarget {
    fn stop_signal(&self) -> u8 {
        self.stop_signal
    }

    fn read_registers(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.regs);
    }

    fn write_registers(&mut self, regs: &[u8]) -> Result<(), GdbStubError> {
        let copy_len = core::cmp::min(self.regs.len(), regs.len());
        self.regs[..copy_len].copy_from_slice(&regs[..copy_len]);
        Ok(())
    }

    fn read_memory(&self, addr: u64, out: &mut [u8]) -> Result<(), GdbStubError> {
        if out.len() > 64 * 1024 {
            return Err(GdbStubError::TargetError);
        }
        let src = addr as *const u8;
        if src.is_null() {
            return Err(GdbStubError::InvalidAddress);
        }
        unsafe {
            core::ptr::copy_nonoverlapping(src, out.as_mut_ptr(), out.len());
        }
        Ok(())
    }

    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), GdbStubError> {
        if data.len() > 64 * 1024 {
            return Err(GdbStubError::TargetError);
        }
        let dst = addr as *mut u8;
        if dst.is_null() {
            return Err(GdbStubError::InvalidAddress);
        }
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
        }
        Ok(())
    }

    fn resume_run(&mut self) {
        self.resume_requested = true;
        self.single_step = false;
    }

    fn single_step_run(&mut self) {
        self.resume_requested = true;
        self.single_step = true;
    }

    fn insert_sw_breakpoint(&mut self, addr: u64, kind: u8) -> Result<(), GdbStubError> {
        if !self.breakpoints.iter().any(|bp| *bp == (addr, kind)) {
            self.breakpoints.push((addr, kind));
        }
        Ok(())
    }

    fn remove_sw_breakpoint(&mut self, addr: u64, kind: u8) -> Result<(), GdbStubError> {
        self.breakpoints.retain(|bp| *bp != (addr, kind));
        Ok(())
    }
}

pub struct GdbStub;

impl GdbStub {
    pub const fn new() -> Self {
        Self
    }

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
                target.resume_run();
                Ok(Some(format!("S{:02x}", target.stop_signal())))
            }
            b's' => {
                target.single_step_run();
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

struct TransportSlot {
    transport: Arc<dyn GdbTransport>,
    rx: Vec<u8>,
}

pub struct GdbServer {
    stub: GdbStub,
    target: PoisonLock<KernelGdbTarget>,
    transports: PoisonLock<Vec<TransportSlot>>,
    active_transport: AtomicUsize,
    enabled: AtomicBool,
}

impl GdbServer {
    pub fn new() -> Self {
        Self {
            stub: GdbStub::new(),
            target: PoisonLock::new(KernelGdbTarget::default()),
            transports: PoisonLock::new(Vec::new()),
            active_transport: AtomicUsize::new(ACTIVE_NONE),
            enabled: AtomicBool::new(false),
        }
    }

    pub fn set_enabled(&self, enabled: bool) {
        if !enabled {
            self.active_transport.store(ACTIVE_NONE, Ordering::Release);
        }
        self.enabled.store(enabled, Ordering::Release);
    }

    pub fn register_transport(&self, transport: Arc<dyn GdbTransport>) -> usize {
        let mut slots = self.transports.lock().unwrap_or_else(|e| e.into_inner());
        slots.push(TransportSlot {
            transport,
            rx: Vec::new(),
        });
        slots.len() - 1
    }

    fn process_one_packet(
        &self,
        idx: usize,
        slot: &mut TransportSlot,
    ) -> Result<bool, GdbStubError> {
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while let Some(b) = slot.transport.try_read_byte() {
            slot.rx.push(b);
            if slot.rx.len() > MAX_PACKET_BUFFER {
                let drop_len = slot.rx.len() - MAX_PACKET_BUFFER;
                slot.rx.drain(..drop_len);
            }
        }

        let Some(packet) = extract_packet(&mut slot.rx) else {
            return Ok(false);
        };

        if self.active_transport.load(Ordering::Acquire) == ACTIVE_NONE {
            self.active_transport.store(idx, Ordering::Release);
        }

        match parse_packet(&packet) {
            Ok(payload) => {
                slot.transport.write_bytes(b"+");
                let response = {
                    let mut target = self.target.lock().unwrap_or_else(|e| e.into_inner());
                    self.stub.handle_payload(payload, &mut *target)?
                };
                if let Some(resp_payload) = response {
                    let framed = frame_packet(&resp_payload);
                    slot.transport.write_bytes(&framed);
                }
            }
            Err(GdbStubError::InvalidChecksum) => {
                slot.transport.write_bytes(b"-");
            }
            Err(e) => return Err(e),
        }

        Ok(true)
    }

    pub fn poll_once(&self) -> bool {
        if !self.enabled.load(Ordering::Acquire) {
            return false;
        }

        let mut slots = self.transports.lock().unwrap_or_else(|e| e.into_inner());
        let active = self.active_transport.load(Ordering::Acquire);

        for (idx, slot) in slots.iter_mut().enumerate() {
            if active != ACTIVE_NONE && active != idx {
                continue;
            }
            if let Ok(true) = self.process_one_packet(idx, slot) {
                return true;
            }
        }
        false
    }

    pub fn on_trap(&self, signal: u8, frame: &InterruptStackFrame) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }

        {
            let mut target = self.target.lock().unwrap_or_else(|e| e.into_inner());
            target.capture_trap(signal, frame);
        }

        // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
        loop {
            let _ = self.poll_once();
            if self
                .target
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .resume_requested
            {
                break;
            }
            core::hint::spin_loop();
        }
    }
}

pub struct SerialCom1Transport;

impl SerialCom1Transport {
    pub const fn new() -> Self {
        Self
    }
}

impl GdbTransport for SerialCom1Transport {
    fn try_read_byte(&self) -> Option<u8> {
        crate::io::serial::try_read_byte()
    }

    fn write_bytes(&self, bytes: &[u8]) {
        for b in bytes {
            crate::io::serial::write_byte(*b);
        }
    }
}

pub struct VirtioConsoleTransport {
    staged_rx: PoisonLock<VecDeque<u8>>,
}

impl VirtioConsoleTransport {
    pub fn new() -> Self {
        Self {
            staged_rx: PoisonLock::new(VecDeque::new()),
        }
    }
}

impl GdbTransport for VirtioConsoleTransport {
    fn try_read_byte(&self) -> Option<u8> {
        {
            let mut staged = self.staged_rx.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(b) = staged.pop_front() {
                return Some(b);
            }
        }

        let dev = crate::io::virtio::console::get_virtio_console_device_at_index(0)?;
        let bytes = dev.read_bytes()?;
        if bytes.is_empty() {
            return None;
        }

        let mut staged = self.staged_rx.lock().unwrap_or_else(|e| e.into_inner());
        for b in bytes {
            staged.push_back(b);
        }
        staged.pop_front()
    }

    fn write_bytes(&self, bytes: &[u8]) {
        if let Some(dev) = crate::io::virtio::console::get_virtio_console_device_at_index(0) {
            let _ = dev.write_bytes(bytes);
        }
    }
}

static GDB_SERVER: spin::Once<GdbServer> = spin::Once::new();

pub fn init_gdb_stub() -> &'static GdbServer {
    GDB_SERVER.call_once(GdbServer::new)
}

pub fn gdb_server() -> Option<&'static GdbServer> {
    GDB_SERVER.get()
}

pub fn gdb_stub() -> Option<&'static GdbStub> {
    GDB_SERVER.get().map(|s| &s.stub)
}

pub fn register_transport(transport: Arc<dyn GdbTransport>) -> Result<usize, GdbStubError> {
    let server = init_gdb_stub();
    Ok(server.register_transport(transport))
}

pub fn poll_once() -> bool {
    gdb_server().map(|s| s.poll_once()).unwrap_or(false)
}

pub fn set_enabled(enabled: bool) {
    let server = init_gdb_stub();
    server.set_enabled(enabled);
}

pub fn on_trap(signal: u8, frame: &InterruptStackFrame) {
    if let Some(server) = gdb_server() {
        server.on_trap(signal, frame);
    }
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

fn extract_packet(rx: &mut Vec<u8>) -> Option<Vec<u8>> {
    let start = rx.iter().position(|b| *b == b'$')?;
    if start > 0 {
        rx.drain(..start);
    }
    let hash = rx.iter().position(|b| *b == b'#')?;
    if hash + 2 >= rx.len() {
        return None;
    }
    let packet = rx[..hash + 3].to_vec();
    rx.drain(..hash + 3);
    Some(packet)
}

#[inline]
fn checksum(payload: &[u8]) -> u8 {
    payload.iter().fold(0u8, |acc, b| acc.wrapping_add(*b))
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
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU32, Ordering};

    #[derive(Default)]
    struct DummyTarget {
        regs: Vec<u8>,
        mem: Vec<u8>,
        breaks: Vec<(u64, u8)>,
        stop: u8,
        continued: AtomicU32,
        stepped: AtomicU32,
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

        fn resume_run(&mut self) {
            self.continued.fetch_add(1, Ordering::Relaxed);
        }

        fn single_step_run(&mut self) {
            self.stepped.fetch_add(1, Ordering::Relaxed);
        }

        fn insert_sw_breakpoint(&mut self, addr: u64, kind: u8) -> Result<(), GdbStubError> {
            self.breaks.push((addr, kind));
            Ok(())
        }

        fn remove_sw_breakpoint(&mut self, addr: u64, kind: u8) -> Result<(), GdbStubError> {
            self.breaks.retain(|b| *b != (addr, kind));
            Ok(())
        }
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
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

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn gdb_packet_roundtrip() {
        let payload = "g";
        let framed = frame_packet(payload);
        let parsed = parse_packet(&framed).expect("packet parse");
        assert_eq!(parsed, payload);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn gdb_required_command_set_smoke() {
        let stub = GdbStub::new();
        let mut target = DummyTarget {
            regs: vec![0xAA, 0xBB, 0xCC],
            mem: vec![0u8; 32],
            stop: 5,
            ..Default::default()
        };

        assert_eq!(
            stub.handle_payload("?", &mut target).expect("stop reply"),
            Some(String::from("S05"))
        );
        assert_eq!(
            stub.handle_payload("g", &mut target).expect("read regs"),
            Some(String::from("aabbcc"))
        );
        assert_eq!(
            stub.handle_payload("G010203", &mut target)
                .expect("write regs"),
            Some(String::from("OK"))
        );
        assert_eq!(target.regs[..3], [1, 2, 3]);

        assert_eq!(
            stub.handle_payload("M2,3:0a0b0c", &mut target)
                .expect("write memory"),
            Some(String::from("OK"))
        );
        assert_eq!(
            stub.handle_payload("m2,3", &mut target)
                .expect("read memory"),
            Some(String::from("0a0b0c"))
        );

        assert_eq!(
            stub.handle_payload("c", &mut target).expect("continue"),
            Some(String::from("S05"))
        );
        assert_eq!(
            target.continued.load(Ordering::Relaxed),
            1,
            "continue callback should be invoked"
        );
        assert_eq!(
            stub.handle_payload("s", &mut target).expect("step"),
            Some(String::from("S05"))
        );
        assert_eq!(
            target.stepped.load(Ordering::Relaxed),
            1,
            "step callback should be invoked"
        );

        assert_eq!(
            stub.handle_payload("Z0,10,1", &mut target)
                .expect("insert breakpoint"),
            Some(String::from("OK"))
        );
        assert!(target.breaks.contains(&(0x10, 1)));

        assert_eq!(
            stub.handle_payload("z0,10,1", &mut target)
                .expect("remove breakpoint"),
            Some(String::from("OK"))
        );
        assert!(!target.breaks.contains(&(0x10, 1)));
    }

    #[derive(Default)]
    struct DummyTransport {
        rx: PoisonLock<VecDeque<u8>>,
        tx: PoisonLock<Vec<u8>>,
    }

    impl DummyTransport {
        fn push_packet(&self, packet: &[u8]) {
            let mut rx = self.rx.lock().unwrap_or_else(|e| e.into_inner());
            for b in packet {
                rx.push_back(*b);
            }
        }

        fn take_tx(&self) -> Vec<u8> {
            let mut tx = self.tx.lock().unwrap_or_else(|e| e.into_inner());
            let out = tx.clone();
            tx.clear();
            out
        }
    }

    impl GdbTransport for DummyTransport {
        fn try_read_byte(&self) -> Option<u8> {
            self.rx
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pop_front()
        }

        fn write_bytes(&self, bytes: &[u8]) {
            self.tx
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend_from_slice(bytes);
        }
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn gdb_server_uses_single_active_transport_lock() {
        let server = GdbServer::new();
        let t0 = Arc::new(DummyTransport::default());
        let t1 = Arc::new(DummyTransport::new());

        let _ = server.register_transport(t0.clone());
        let _ = server.register_transport(t1.clone());
        server.set_enabled(true);

        let pkt = frame_packet("?");
        t0.push_packet(&pkt);
        t1.push_packet(&pkt);

        assert!(
            server.poll_once(),
            "first transport packet should be handled"
        );

        let tx0 = t0.take_tx();
        assert_eq!(tx0, vec![b'+', b'$', b'S', b'0', b'5', b'#', b'b', b'8']);

        let tx1 = t1.take_tx();
        assert!(
            tx1.is_empty(),
            "second transport should stay inactive until active lock is released"
        );
    }

    impl DummyTransport {
        fn new() -> Self {
            Self {
                rx: PoisonLock::new(VecDeque::new()),
                tx: PoisonLock::new(Vec::new()),
            }
        }
    }
}
