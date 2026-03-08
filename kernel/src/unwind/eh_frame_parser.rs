use super::*;

// ============================================================================
// 型安全版 .eh_frame パーサー（MemoryReader使用）
// ============================================================================

mod catch_panic;
pub use self::catch_panic::*;

pub struct SafeEhFrameParser<'a> {
    pub(crate) reader: MemoryReader<'a>,
    cie_cache_offsets: [u64; 16],
    cie_cache_entries: [Option<SafeCie>; 16],
    cie_cache_len: usize,
}

#[derive(Debug, Clone)]
pub struct SafeCie {
    pub version: u8,
    pub augmentation: AugmentationData,
    pub code_alignment_factor: u64,
    pub data_alignment_factor: i64,
    pub return_address_register: DwarfRegister,
    pub initial_instructions_offset: usize,
    pub initial_instructions_len: usize,
}

#[derive(Debug, Clone)]
pub struct SafeFde {
    pub cie_offset: u64,
    pub initial_location: u64,
    pub address_range: u64,
    pub instructions_offset: usize,
    pub instructions_len: usize,
}

#[derive(Debug, Clone, Default)]
pub struct AugmentationData {
    pub has_lsda: bool,
    pub lsda_encoding: Option<u8>,
    pub has_personality: bool,
    pub personality_encoding: Option<u8>,
    pub personality_address: Option<u64>,
    pub fde_encoding: Option<u8>,
    pub is_signal_frame: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeCfiInstruction {
    DefCfa { register: DwarfRegister, offset: u64 },
    DefCfaRegister { register: DwarfRegister },
    DefCfaOffset { offset: u64 },
    Offset { register: DwarfRegister, offset: i64 },
    SameValue { register: DwarfRegister },
    Undefined { register: DwarfRegister },
    Register { register: DwarfRegister, source: DwarfRegister },
    AdvanceLoc { delta: u64 },
    RememberState,
    RestoreState,
    Nop,
}

impl<'a> SafeEhFrameParser<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        const NONE_CIE: Option<SafeCie> = None;
        Self {
            reader: MemoryReader::new(data),
            cie_cache_offsets: [0; 16],
            cie_cache_entries: [NONE_CIE; 16],
            cie_cache_len: 0,
        }
    }

    pub(super) fn process_eh_frame_entry(
        &mut self,
        entry_start: usize,
        length: u64,
        pc: u64,
    ) -> Option<Option<SafeFde>> {
        let entry_end = self.reader.position() + length as usize;
        let cie_id = self.reader.read_u32().ok()?;
        if cie_id == 0 {
            let cie = self.parse_cie_content(length as usize - 4)?;
            self.cache_cie(entry_start as u64, cie);
            self.reader.set_position(entry_end);
            return Some(None);
        }
        let cie_offset = entry_start as u64 + 4 - cie_id as u64;
        let fde_encoding = self.get_cached_cie(cie_offset).and_then(|c| c.augmentation.fde_encoding).unwrap_or(0x03);
        let initial_location = self.read_encoded_value(fde_encoding)?;
        let address_range = self.read_encoded_value(fde_encoding & 0x0F)?;
        if pc >= initial_location && pc < initial_location + address_range {
            let instructions_offset = self.reader.position();
            let instructions_len = entry_end.saturating_sub(instructions_offset);
            return Some(Some(SafeFde { cie_offset, initial_location, address_range, instructions_offset, instructions_len }));
        }
        self.reader.set_position(entry_end);
        Some(None)
    }

    pub fn find_fde(&mut self, pc: u64) -> Option<SafeFde> {
        self.reader.set_position(0);
        while !self.reader.is_empty() {
            let entry_start = self.reader.position();
            let length = self.reader.read_u32().ok()? as u64;
            if length == 0 { break; }
            let length = if length == 0xFFFFFFFF { self.reader.read_u64().ok()? } else { length };
            match self.process_eh_frame_entry(entry_start, length, pc) {
                Some(Some(fde)) => return Some(fde),
                Some(None) => continue,
                None => return None,
            }
        }
        None
    }

    pub(super) fn parse_cie_content(&mut self, remaining_len: usize) -> Option<SafeCie> {
        let content_start = self.reader.position();
        let version = self.reader.read_u8().ok()?;
        if version != 1 && version != 3 { return None; }
        let mut augmentation = AugmentationData::default();
        let aug_string = self.read_null_terminated_string()?;
        let code_alignment_factor = self.reader.read_uleb128().ok()?;
        let data_alignment_factor = self.reader.read_sleb128().ok()?;
        let ra_reg = if version == 1 { self.reader.read_u8().ok()? as u64 } else { self.reader.read_uleb128().ok()? };
        let return_address_register = DwarfRegister::from_dwarf_number(ra_reg as u8)?;
        if aug_string.starts_with(b"z") {
            let aug_len = self.reader.read_uleb128().ok()? as usize;
            let aug_end = self.reader.position() + aug_len;
            for &ch in aug_string.iter().skip(1) {
                match ch {
                    b'L' => { augmentation.has_lsda = true; augmentation.lsda_encoding = Some(self.reader.read_u8().ok()?); }
                    b'P' => {
                        augmentation.has_personality = true;
                        let encoding = self.reader.read_u8().ok()?;
                        augmentation.personality_encoding = Some(encoding);
                        augmentation.personality_address = Some(self.read_encoded_value(encoding)?);
                    }
                    b'R' => { augmentation.fde_encoding = Some(self.reader.read_u8().ok()?); }
                    b'S' => { augmentation.is_signal_frame = true; }
                    _ => {}
                }
            }
            self.reader.set_position(aug_end);
        }
        let initial_instructions_offset = self.reader.position();
        let initial_instructions_len = content_start + remaining_len - initial_instructions_offset;
        Some(SafeCie { version, augmentation, code_alignment_factor, data_alignment_factor, return_address_register, initial_instructions_offset, initial_instructions_len })
    }

    pub(super) fn cache_cie(&mut self, offset: u64, cie: SafeCie) {
        if self.cie_cache_len < self.cie_cache_offsets.len() {
            self.cie_cache_offsets[self.cie_cache_len] = offset;
            self.cie_cache_entries[self.cie_cache_len] = Some(cie);
            self.cie_cache_len += 1;
        }
    }

    pub(super) fn get_cached_cie(&self, offset: u64) -> Option<&SafeCie> {
        for i in 0..self.cie_cache_len {
            if self.cie_cache_offsets[i] == offset { return self.cie_cache_entries[i].as_ref(); }
        }
        None
    }

    pub(super) fn read_null_terminated_string(&mut self) -> Option<&'a [u8]> {
        let start = self.reader.position();
        loop { if self.reader.read_u8().ok()? == 0 { break; } }
        let end = self.reader.position() - 1;
        Some(&self.reader.data()[start..end])
    }

    pub(super) fn read_unsigned_format(&mut self, format: u8) -> Option<u64> {
        match format {
            0x00 | 0x04 => Some(self.reader.read_u64().ok()?),
            0x01 => Some(self.reader.read_uleb128().ok()?),
            0x02 => Some(self.reader.read_u16().ok()? as u64),
            0x03 => Some(self.reader.read_u32().ok()? as u64),
            _ => None,
        }
    }

    pub(super) fn read_signed_format(&mut self, format: u8) -> Option<u64> {
        match format {
            0x09 => Some(self.reader.read_sleb128().ok()? as u64),
            0x0A => Some(self.reader.read_i16().ok()? as u64),
            0x0B => Some(self.reader.read_i32().ok()? as u64),
            0x0C => Some(self.reader.read_i64().ok()? as u64),
            _ => None,
        }
    }

    pub(super) fn read_encoded_value(&mut self, encoding: u8) -> Option<u64> {
        let format = encoding & 0x0F;
        if format <= 0x04 { self.read_unsigned_format(format) } else { self.read_signed_format(format) }
    }

    pub fn parse_instruction(&mut self, data_align: i64) -> Option<SafeCfiInstruction> {
        let opcode = self.reader.read_u8().ok()?;
        let high2 = opcode & 0xC0;
        let low6 = opcode & 0x3F;
        match high2 {
            0x00 => self.parse_extended_instruction(low6, data_align),
            0x40 => Some(SafeCfiInstruction::AdvanceLoc { delta: low6 as u64 }),
            0x80 => {
                let register = DwarfRegister::from_dwarf_number(low6)?;
                let offset = self.reader.read_uleb128().ok()? as i64 * data_align;
                Some(SafeCfiInstruction::Offset { register, offset })
            }
            0xC0 => {
                let register = DwarfRegister::from_dwarf_number(low6)?;
                Some(SafeCfiInstruction::SameValue { register })
            }
            _ => None,
        }
    }

    pub(super) fn parse_extended_instruction(&mut self, opcode: u8, data_align: i64) -> Option<SafeCfiInstruction> {
        match opcode {
            0x00 => Some(SafeCfiInstruction::Nop),
            0x02..=0x04 => self.parse_advance_loc_extended(opcode),
            0x05..=0x09 => self.parse_register_rule_instruction(opcode, data_align),
            0x0A => Some(SafeCfiInstruction::RememberState),
            0x0B => Some(SafeCfiInstruction::RestoreState),
            0x0C..=0x0E => self.parse_cfa_instruction(opcode),
            _ => None,
        }
    }

    pub(super) fn parse_advance_loc_extended(&mut self, opcode: u8) -> Option<SafeCfiInstruction> {
        let delta = match opcode {
            0x02 => self.reader.read_u8().ok()? as u64,
            0x03 => self.reader.read_u16().ok()? as u64,
            0x04 => self.reader.read_u32().ok()? as u64,
            _ => return None,
        };
        Some(SafeCfiInstruction::AdvanceLoc { delta })
    }

    pub(super) fn parse_register_rule_instruction(&mut self, opcode: u8, data_align: i64) -> Option<SafeCfiInstruction> {
        let reg = self.reader.read_uleb128().ok()? as u8;
        let register = DwarfRegister::from_dwarf_number(reg)?;
        match opcode {
            0x05 => {
                let offset = self.reader.read_uleb128().ok()? as i64 * data_align;
                Some(SafeCfiInstruction::Offset { register, offset })
            }
            0x06 => Some(SafeCfiInstruction::SameValue { register }),
            0x07 => Some(SafeCfiInstruction::Undefined { register }),
            0x08 => Some(SafeCfiInstruction::SameValue { register }),
            0x09 => {
                let src = self.reader.read_uleb128().ok()? as u8;
                let source = DwarfRegister::from_dwarf_number(src)?;
                Some(SafeCfiInstruction::Register { register, source })
            }
            _ => None,
        }
    }

    pub(super) fn parse_cfa_instruction(&mut self, opcode: u8) -> Option<SafeCfiInstruction> {
        match opcode {
            0x0C => {
                let reg = self.reader.read_uleb128().ok()? as u8;
                let register = DwarfRegister::from_dwarf_number(reg)?;
                let offset = self.reader.read_uleb128().ok()?;
                Some(SafeCfiInstruction::DefCfa { register, offset })
            }
            0x0D => {
                let reg = self.reader.read_uleb128().ok()? as u8;
                let register = DwarfRegister::from_dwarf_number(reg)?;
                Some(SafeCfiInstruction::DefCfaRegister { register })
            }
            0x0E => {
                let offset = self.reader.read_uleb128().ok()?;
                Some(SafeCfiInstruction::DefCfaOffset { offset })
            }
            _ => None,
        }
    }
}

pub struct SafeCfiInterpreter {
    context: registers::UnwindContext,
    state_stack: [registers::UnwindContext; 4],
    state_stack_valid: [bool; 4],
    state_stack_len: usize,
    location: u64,
    code_alignment_factor: u64,
}

impl SafeCfiInterpreter {
    pub fn new(code_alignment_factor: u64, _data_alignment_factor: i64) -> Self {
        Self {
            context: registers::UnwindContext::new(),
            state_stack: [registers::UnwindContext::new(), registers::UnwindContext::new(), registers::UnwindContext::new(), registers::UnwindContext::new()],
            state_stack_valid: [false; 4],
            state_stack_len: 0,
            location: 0,
            code_alignment_factor,
        }
    }

    pub fn execute(&mut self, instruction: SafeCfiInstruction) {
        match instruction {
            SafeCfiInstruction::DefCfa { register, offset } => { self.context.set_cfa(registers::CfaRule::RegisterOffset { register, offset: offset as i64 }); }
            SafeCfiInstruction::DefCfaRegister { register } => { if let registers::CfaRule::RegisterOffset { offset, .. } = self.context.cfa() { self.context.set_cfa(registers::CfaRule::RegisterOffset { register, offset: *offset }); } }
            SafeCfiInstruction::DefCfaOffset { offset } => { if let registers::CfaRule::RegisterOffset { register, .. } = self.context.cfa() { self.context.set_cfa(registers::CfaRule::RegisterOffset { register: *register, offset: offset as i64 }); } }
            SafeCfiInstruction::Offset { register, offset } => { self.context.set_register_rule(register, registers::RegisterRule::Offset(offset)); }
            SafeCfiInstruction::SameValue { register } => { self.context.set_register_rule(register, registers::RegisterRule::SameValue); }
            SafeCfiInstruction::Undefined { register } => { self.context.set_register_rule(register, registers::RegisterRule::Undefined); }
            SafeCfiInstruction::Register { register, source } => { self.context.set_register_rule(register, registers::RegisterRule::Register(source)); }
            SafeCfiInstruction::AdvanceLoc { delta } => { self.location += delta * self.code_alignment_factor; }
            SafeCfiInstruction::RememberState => { if self.state_stack_len < self.state_stack.len() { self.state_stack[self.state_stack_len].copy_from(&self.context); self.state_stack_valid[self.state_stack_len] = true; self.state_stack_len += 1; } }
            SafeCfiInstruction::RestoreState => { if self.state_stack_len > 0 { self.state_stack_len -= 1; if self.state_stack_valid[self.state_stack_len] { self.context.copy_from(&self.state_stack[self.state_stack_len]); self.state_stack_valid[self.state_stack_len] = false; } } }
            SafeCfiInstruction::Nop => {}
        }
    }

    pub fn location(&self) -> u64 { self.location }
    pub fn context(&self) -> &registers::UnwindContext { &self.context }
}

use crate::sync::PoisonLock;
use alloc::string::String;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub(crate) static PANIC_CATCH_ACTIVE: AtomicBool = AtomicBool::new(false);
pub(crate) static PANIC_CAUGHT: AtomicBool = AtomicBool::new(false);
pub(crate) const PANIC_MESSAGE_BUFFER_SIZE: usize = 256;
pub(crate) static PANIC_MESSAGE_BUFFER: PoisonLock<[u8; PANIC_MESSAGE_BUFFER_SIZE]> =
    PoisonLock::new([0u8; PANIC_MESSAGE_BUFFER_SIZE]);
pub(crate) static PANIC_MESSAGE_LEN: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone)]
pub struct PanicPayload {
    pub message: String,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub column: Option<u32>,
}

impl PanicPayload {
    pub fn empty() -> Self { Self { message: String::new(), file: None, line: None, column: None } }
    pub fn from_message(message: String) -> Self { Self { message, file: None, line: None, column: None } }
}

impl core::fmt::Display for PanicPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.message)?;
        if let (Some(file), Some(line)) = (&self.file, self.line) {
            write!(f, " at {}:{}", file, line)?;
            if let Some(col) = self.column { write!(f, ":{}", col)?; }
        }
        Ok(())
    }
}

pub type CatchResult<T> = Result<T, PanicPayload>;

#[inline]
pub fn is_panic_catch_active() -> bool { PANIC_CATCH_ACTIVE.load(Ordering::SeqCst) }

pub fn record_caught_panic(
    message: &str,
    file: Option<&str>,
    line: Option<u32>,
    column: Option<u32>,
) {
    PANIC_CAUGHT.store(true, Ordering::SeqCst);
    let bytes = message.as_bytes();
    let copy_len = bytes.len().min(PANIC_MESSAGE_BUFFER_SIZE - 1);
    if let Ok(mut guard) = PANIC_MESSAGE_BUFFER.try_lock() {
        guard[..copy_len].copy_from_slice(&bytes[..copy_len]);
        guard[copy_len] = 0;
        PANIC_MESSAGE_LEN.store(copy_len, Ordering::Release);
    }
    let _ = (file, line, column);
}

pub(crate) fn take_caught_panic() -> Option<PanicPayload> {
    if !PANIC_CAUGHT.swap(false, Ordering::SeqCst) { return None; }
    let len = PANIC_MESSAGE_LEN.load(Ordering::Acquire);
    let message = if let Ok(guard) = PANIC_MESSAGE_BUFFER.try_lock() {
        let bytes = &guard[..len];
        String::from_utf8_lossy(bytes).into_owned()
    } else if let Some(e) = PANIC_MESSAGE_BUFFER.try_lock().err() {
        // Poisoned
        let bytes = &e.into_inner()[..len];
        String::from_utf8_lossy(bytes).into_owned()
    } else {
        String::from("(panic message unavailable)")
    };
    PANIC_MESSAGE_LEN.store(0, Ordering::Release);
    Some(PanicPayload::from_message(message))
}
