// ============================================================================
// src/graphics/bsod.rs - Blue Screen of Death Display
// ============================================================================
//!
//! # BSOD (Blue Screen of Death) Display Module
//!
//! Fills the screen with blue and displays error details, stack trace, and registers
//! when a kernel panic occurs.
//!
//! ## Features
//! - Blue screen background
//! - Error message and location
//! - Stack trace
//! - CPU register dump
//! - Lock-free and Allocation-free design for panic safety
//!
use core::fmt::Write;

use super::{BitmapFont, Color, Font, Framebuffer, Rect, with_framebuffer};
use crate::unwind::{Backtrace, StackFrame};

// ============================================================================
// BSOD Color Palette
// ============================================================================

pub mod colors {
    use super::Color;
    pub const BACKGROUND: Color = Color::new(0x00, 0x78, 0xD7);
    pub const SAD_FACE: Color = Color::new(0xFF, 0xFF, 0xFF);
    pub const TEXT_PRIMARY: Color = Color::new(0xFF, 0xFF, 0xFF);
    pub const TEXT_SECONDARY: Color = Color::new(0xCC, 0xCC, 0xCC);
    pub const ERROR_CODE: Color = Color::new(0xFF, 0xFF, 0x00);
    pub const SEPARATOR: Color = Color::new(0x40, 0x90, 0xE0);
    pub const QR_LIGHT: Color = Color::new(0xFF, 0xFF, 0xFF);
    pub const QR_DARK: Color = Color::new(0x00, 0x00, 0x00);
}

// ============================================================================
// Internal Formatting Utilities (Stack Based)
// ============================================================================

pub struct StackFmtWriter<'a> {
    buffer: &'a mut [u8],
    offset: usize,
}

impl<'a> StackFmtWriter<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, offset: 0 }
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buffer[..self.offset]).unwrap_or("FMT_ERR")
    }
}

impl<'a> Write for StackFmtWriter<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let remaining = self.buffer.len() - self.offset;
        let bytes = s.as_bytes();
        let len = bytes.len().min(remaining);

        if len > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    self.buffer.as_mut_ptr().add(self.offset),
                    len,
                );
            }
            self.offset += len;
        }
        Ok(())
    }
}

// ============================================================================
// BSOD Info Structure (No Alloc)
// ============================================================================

pub struct BsodInfo<'a> {
    pub message: &'a str,
    pub file: Option<&'a str>,
    pub line: Option<u32>,
    pub column: Option<u32>,
    pub backtrace: Option<Backtrace>,
    pub registers: Option<RegisterDump>,
    pub error_code: &'a str,
}

impl<'a> BsodInfo<'a> {
    pub fn new(message: &'a str) -> Self {
        Self {
            message,
            file: None,
            line: None,
            column: None,
            backtrace: None,
            registers: None,
            error_code: "KERNEL_PANIC",
        }
    }

    pub fn with_location(mut self, file: &'a str, line: u32, column: u32) -> Self {
        self.file = Some(file);
        self.line = Some(line);
        self.column = Some(column);
        self
    }

    pub fn with_backtrace(mut self, backtrace: Backtrace) -> Self {
        self.backtrace = Some(backtrace);
        self
    }

    pub fn with_registers(mut self, registers: RegisterDump) -> Self {
        self.registers = Some(registers);
        self
    }

    pub fn with_error_code(mut self, code: &'a str) -> Self {
        self.error_code = code;
        self
    }
}

#[derive(Clone, Debug, Copy)]
pub struct RegisterDump {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
}

impl RegisterDump {
    pub fn capture() -> Self {
        let (rax, rbx, rcx, rdx): (u64, u64, u64, u64);
        let (rsi, rdi, rbp, rsp): (u64, u64, u64, u64);
        let (r8, r9, r10, r11): (u64, u64, u64, u64);
        let (r12, r13, r14, r15): (u64, u64, u64, u64);
        let rflags: u64;
        let cr0: u64;
        let cr2: u64;
        let cr3: u64;
        let cr4: u64;

        unsafe {
            core::arch::asm!(
                "mov {rax}, rax", "mov {rbx}, rbx", "mov {rcx}, rcx", "mov {rdx}, rdx",
                rax = out(reg) rax, rbx = out(reg) rbx, rcx = out(reg) rcx, rdx = out(reg) rdx,
                options(nostack, preserves_flags)
            );
            core::arch::asm!(
                "mov {rsi}, rsi", "mov {rdi}, rdi", "mov {rbp}, rbp", "mov {rsp}, rsp",
                rsi = out(reg) rsi, rdi = out(reg) rdi, rbp = out(reg) rbp, rsp = out(reg) rsp,
                options(nostack, preserves_flags)
            );
            core::arch::asm!(
                "mov {r8}, r8", "mov {r9}, r9", "mov {r10}, r10", "mov {r11}, r11",
                r8 = out(reg) r8, r9 = out(reg) r9, r10 = out(reg) r10, r11 = out(reg) r11,
                options(nostack, preserves_flags)
            );
            core::arch::asm!(
                "mov {r12}, r12", "mov {r13}, r13", "mov {r14}, r14", "mov {r15}, r15",
                r12 = out(reg) r12, r13 = out(reg) r13, r14 = out(reg) r14, r15 = out(reg) r15,
                options(nostack, preserves_flags)
            );
            core::arch::asm!(
                "pushfq", "pop {rflags}",
                rflags = out(reg) rflags,
                options(preserves_flags)
            );
            core::arch::asm!(
                "mov {cr0}, cr0", "mov {cr2}, cr2", "mov {cr3}, cr3", "mov {cr4}, cr4",
                cr0 = out(reg) cr0, cr2 = out(reg) cr2, cr3 = out(reg) cr3, cr4 = out(reg) cr4,
                options(nostack, preserves_flags)
            );
        }

        let rip: u64;
        unsafe {
            core::arch::asm!("lea {rip}, [rip]", rip = out(reg) rip, options(nostack, preserves_flags));
        }

        Self {
            rax,
            rbx,
            rcx,
            rdx,
            rsi,
            rdi,
            rbp,
            rsp,
            r8,
            r9,
            r10,
            r11,
            r12,
            r13,
            r14,
            r15,
            rip,
            rflags,
            cr0,
            cr2,
            cr3,
            cr4,
        }
    }
}

// ============================================================================
// Serial Dump Helper
// ============================================================================

pub fn dump_bsod_info_to_serial(info: &BsodInfo) {
    use crate::io::log::{early_print, early_print_dec, early_print_hex};

    early_print("\n[PANIC] ");
    early_print(info.message);
    early_print("\n");

    if let (Some(file), Some(line), Some(col)) = (info.file, info.line, info.column) {
        early_print("[PANIC] Location: ");
        early_print(file);
        early_print(":");
        early_print_dec(line as u64);
        early_print(":");
        early_print_dec(col as u64);
        early_print("\n");
    }

    if let Some(regs) = &info.registers {
        early_print("[PANIC] Registers:\n");
        // Row 1
        early_print("RAX=");
        early_print_hex(regs.rax);
        early_print(" RBX=");
        early_print_hex(regs.rbx);
        early_print(" RCX=");
        early_print_hex(regs.rcx);
        early_print("\n");
        // Row 2
        early_print("RDX=");
        early_print_hex(regs.rdx);
        early_print(" RSI=");
        early_print_hex(regs.rsi);
        early_print(" RDI=");
        early_print_hex(regs.rdi);
        early_print("\n");
        // Row 3
        early_print("RBP=");
        early_print_hex(regs.rbp);
        early_print(" RSP=");
        early_print_hex(regs.rsp);
        early_print(" RIP=");
        early_print_hex(regs.rip);
        early_print("\n");
        // Row 4
        early_print("R8 =");
        early_print_hex(regs.r8);
        early_print(" R9 =");
        early_print_hex(regs.r9);
        early_print(" R10=");
        early_print_hex(regs.r10);
        early_print("\n");
        // Row 5
        early_print("R11=");
        early_print_hex(regs.r11);
        early_print(" R12=");
        early_print_hex(regs.r12);
        early_print(" R13=");
        early_print_hex(regs.r13);
        early_print("\n");
        // Row 6
        early_print("R14=");
        early_print_hex(regs.r14);
        early_print(" R15=");
        early_print_hex(regs.r15);
        early_print(" FLG=");
        early_print_hex(regs.rflags);
        early_print("\n");
        // CRs
        early_print("CR0=");
        early_print_hex(regs.cr0);
        early_print(" CR2=");
        early_print_hex(regs.cr2);
        early_print(" CR3=");
        early_print_hex(regs.cr3);
        early_print("\n");
    }

    if let Some(bt) = &info.backtrace {
        early_print("[PANIC] Stack Trace:\n");
        for entry in bt.iter().take(10) {
            early_print("  #");
            early_print_dec(entry.frame_number as u64);
            early_print(" IP=");
            early_print_hex(entry.frame.instruction_pointer as u64);
            early_print(" SP=");
            early_print_hex(entry.frame.stack_pointer as u64);
            early_print("\n");
        }
        if bt.len() > 10 {
            early_print("  ... and more\n");
        }
    }
}

// ============================================================================
// Drawing Functions
// ============================================================================

fn draw_sad_face(fb: &mut Framebuffer, x: i32, y: i32, scale: u32) {
    let color = colors::SAD_FACE;
    let radius = (scale * 30) as i32;
    fb.draw_circle(x + radius, y + radius, radius, color);
    fb.draw_circle(x + radius, y + radius, radius - 1, color);

    let eye_y = y + (scale * 20) as i32;
    let left_eye_x = x + (scale * 18) as i32;
    let right_eye_x = x + (scale * 42) as i32;
    fb.fill_rect(Rect::new(left_eye_x, eye_y, scale * 4, scale * 4), color);
    fb.fill_rect(Rect::new(right_eye_x, eye_y, scale * 4, scale * 4), color);

    let mouth_y = y + (scale * 40) as i32;
    let mouth_x = x + (scale * 15) as i32;
    for i in 0..(scale * 30) as i32 {
        let offset = (((i - (scale * 15) as i32).pow(2)) / (scale * 8) as i32).min(5);
        fb.set_pixel(mouth_x + i, mouth_y + offset, color);
    }
}

fn draw_section_header(fb: &mut Framebuffer, x: i32, y: i32, title: &str, width: u32) {
    let font = BitmapFont::default_8x16();
    fb.fill_rect(Rect::new(x, y, width, 2), colors::SEPARATOR);
    font.draw_string(fb, x, y + 6, title, colors::TEXT_PRIMARY, None);
}

fn draw_register(fb: &mut Framebuffer, x: i32, y: i32, name: &str, value: u64) {
    let font = BitmapFont::default_8x16();
    let mut buf_arr = [0u8; 32];
    let mut writer = StackFmtWriter::new(&mut buf_arr);
    let _ = write!(writer, "{:<4} = {:#018x}", name, value);
    font.draw_string(fb, x, y, writer.as_str(), colors::TEXT_SECONDARY, None);
}

pub fn display_bsod(info: &BsodInfo) {
    with_framebuffer(|fb| {
        display_bsod_internal(fb, info);
    });
}

pub fn display_bsod_direct(fb: &mut Framebuffer, info: &BsodInfo) {
    display_bsod_internal(fb, info);
}

fn display_bsod_internal(fb: &mut Framebuffer, info: &BsodInfo) {
    let width = fb.width();
    let height = fb.height();
    let font = BitmapFont::default_8x16();

    fb.clear(colors::BACKGROUND);

    let margin_x = (width / 20).max(40) as i32;
    let margin_y = (height / 15).max(30) as i32;
    let content_width = width - (margin_x as u32 * 2);

    let mut y = margin_y;

    let face_scale = (width / 400).max(1).min(3);
    draw_sad_face(fb, margin_x, y, face_scale);

    let text_x = margin_x + (face_scale * 70) as i32;
    font.draw_string(
        fb,
        text_x,
        y + 10,
        "Your PC ran into a problem and needs to restart.",
        colors::TEXT_PRIMARY,
        None,
    );
    font.draw_string(
        fb,
        text_x,
        y + 30,
        "We're just collecting some error info, and then we'll",
        colors::TEXT_SECONDARY,
        None,
    );
    font.draw_string(
        fb,
        text_x,
        y + 50,
        "restart for you.",
        colors::TEXT_SECONDARY,
        None,
    );

    y += (face_scale * 70) as i32 + 20;

    y = draw_error_message_section(fb, &font, info, margin_x, y, content_width);
    y = draw_stack_trace_section(fb, &font, info, margin_x, y, content_width, height);
    draw_registers_section(fb, &font, info, margin_x, y, content_width);
    draw_bsod_footer(
        fb,
        &font,
        info,
        margin_x,
        margin_y,
        width,
        height,
        content_width,
    );
}

fn draw_error_message_section(
    fb: &mut Framebuffer,
    font: &BitmapFont,
    info: &BsodInfo,
    margin_x: i32,
    mut y: i32,
    content_width: u32,
) -> i32 {
    draw_section_header(fb, margin_x, y, "[ ERROR ]", content_width);
    y += 30;

    let max_len_chars = ((content_width / 8) as usize).max(10);
    y = wrap_and_draw_message(fb, font, info.message, margin_x, y, max_len_chars);
    y = draw_location_info(fb, font, info, margin_x, y);

    y + 10
}

/// Find a word-break point in `msg_bytes` starting at `current_pos` within `max_len` chars.
/// Returns `(split_end, next_start)` where `split_end` is the byte to split at
/// and `next_start` is the first non-space byte after the split.
fn find_word_break(msg_bytes: &[u8], current_pos: usize, max_len: usize) -> (usize, usize) {
    let end = (current_pos + max_len).min(msg_bytes.len());
    let mut split = end;
    if split < msg_bytes.len() {
        let scan_start = if split > 10 { split - 10 } else { current_pos };
        for i in (scan_start..split).rev() {
            if msg_bytes[i] == b' ' {
                split = i;
                break;
            }
        }
    }
    if split == current_pos {
        split = end;
    }
    let mut next = split;
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while next < msg_bytes.len() && msg_bytes[next] == b' ' {
        next += 1;
    }
    (split, next)
}

/// Draw up to 5 word-wrapped lines of a message. Returns the updated y position.
fn wrap_and_draw_message(
    fb: &mut Framebuffer,
    font: &BitmapFont,
    msg: &str,
    margin_x: i32,
    mut y: i32,
    max_len_chars: usize,
) -> i32 {
    let msg_bytes = msg.as_bytes();
    let mut current_pos = 0;
    let mut line_count = 0;
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while current_pos < msg_bytes.len() && line_count < 5 {
        let (split, next) = find_word_break(msg_bytes, current_pos, max_len_chars);
        if let Ok(sub) = core::str::from_utf8(&msg_bytes[current_pos..split]) {
            font.draw_string(fb, margin_x, y, sub, colors::ERROR_CODE, None);
        }
        y += 18;
        current_pos = next;
        line_count += 1;
    }
    y
}

/// Draw file:line:col location info if available. Returns the updated y position.
fn draw_location_info(
    fb: &mut Framebuffer,
    font: &BitmapFont,
    info: &BsodInfo,
    margin_x: i32,
    mut y: i32,
) -> i32 {
    if let (Some(file), Some(line), Some(col)) = (info.file, info.line, info.column) {
        let mut buf = [0u8; 128];
        let mut w = StackFmtWriter::new(&mut buf);
        let _ = write!(w, "at {}:{}:{}", file, line, col);
        font.draw_string(fb, margin_x, y, w.as_str(), colors::TEXT_SECONDARY, None);
        y += 18;
    }
    y
}

fn draw_stack_trace_section(
    fb: &mut Framebuffer,
    font: &BitmapFont,
    info: &BsodInfo,
    margin_x: i32,
    mut y: i32,
    content_width: u32,
    height: u32,
) -> i32 {
    draw_section_header(fb, margin_x, y, "[ STACK TRACE ]", content_width);
    y += 30;

    if let Some(ref bt) = info.backtrace {
        let max_frames = ((height as i32 - y - 200) / 18).max(3).min(10) as usize;
        for entry in bt.iter().take(max_frames) {
            let mut buf = [0u8; 64];
            let mut w = StackFmtWriter::new(&mut buf);
            let _ = write!(
                w,
                "#{:2} {:#018x} (SP: {:#018x})",
                entry.frame_number, entry.frame.instruction_pointer, entry.frame.stack_pointer
            );
            font.draw_string(fb, margin_x, y, w.as_str(), colors::TEXT_SECONDARY, None);
            y += 18;
        }
        if bt.len() > max_frames {
            let mut buf = [0u8; 32];
            let mut w = StackFmtWriter::new(&mut buf);
            let _ = write!(w, "    ... and {} more frames", bt.len() - max_frames);
            font.draw_string(fb, margin_x, y, w.as_str(), colors::TEXT_SECONDARY, None);
            y += 18;
        }
    } else {
        font.draw_string(
            fb,
            margin_x,
            y,
            "  (no backtrace available)",
            colors::TEXT_SECONDARY,
            None,
        );
        y += 18;
    }

    y + 10
}

fn draw_registers_section(
    fb: &mut Framebuffer,
    font: &BitmapFont,
    info: &BsodInfo,
    margin_x: i32,
    mut y: i32,
    content_width: u32,
) {
    draw_section_header(fb, margin_x, y, "[ REGISTERS ]", content_width);
    y += 30;

    if let Some(ref regs) = info.registers {
        let col_width = (content_width / 3) as i32;
        let regs_row1 = [("RAX", regs.rax), ("RBX", regs.rbx), ("RCX", regs.rcx)];
        let regs_row2 = [("RDX", regs.rdx), ("RSI", regs.rsi), ("RDI", regs.rdi)];
        let regs_row3 = [("RBP", regs.rbp), ("RSP", regs.rsp), ("RIP", regs.rip)];
        let regs_row4 = [("R8 ", regs.r8), ("R9 ", regs.r9), ("R10", regs.r10)];
        let regs_row5 = [("R11", regs.r11), ("R12", regs.r12), ("R13", regs.r13)];
        let regs_row6 = [("R14", regs.r14), ("R15", regs.r15), ("FLG", regs.rflags)];

        for (i, row) in [
            regs_row1, regs_row2, regs_row3, regs_row4, regs_row5, regs_row6,
        ]
        .iter()
        .enumerate()
        {
            for (j, (name, value)) in row.iter().enumerate() {
                draw_register(fb, margin_x + (j as i32 * col_width), y, name, *value);
            }
            y += 18;
            if i >= 3 {
                break;
            }
        }
        y += 5;
        let cr_row = [("CR0", regs.cr0), ("CR2", regs.cr2), ("CR3", regs.cr3)];
        for (j, (name, value)) in cr_row.iter().enumerate() {
            draw_register(fb, margin_x + (j as i32 * col_width), y, name, *value);
        }
    } else {
        font.draw_string(
            fb,
            margin_x,
            y,
            "  (registers not captured)",
            colors::TEXT_SECONDARY,
            None,
        );
    }
}

fn draw_bsod_footer(
    fb: &mut Framebuffer,
    font: &BitmapFont,
    info: &BsodInfo,
    margin_x: i32,
    margin_y: i32,
    width: u32,
    height: u32,
    _content_width: u32,
) {
    let qr_total_size = (21 + 4) * 4;
    let qr_x = (width - qr_total_size - margin_x as u32) as i32;
    let qr_y = (height - qr_total_size - margin_y as u32) as i32;

    if let Some(qr) = super::qrcode::generate_error_qr(info.error_code) {
        qr.draw(
            fb,
            qr_x,
            qr_y,
            4, // scale 4x
            colors::QR_DARK,
            colors::QR_LIGHT,
        );
    } else {
        font.draw_string(
            fb,
            qr_x,
            qr_y,
            "QR Gen Failed",
            colors::TEXT_SECONDARY,
            None,
        );
    }

    let stop_y = (height - margin_y as u32 - 40) as i32;
    let mut buf = [0u8; 64];
    let mut w = StackFmtWriter::new(&mut buf);
    let _ = write!(w, "Stop code: {}", info.error_code);
    font.draw_string(fb, margin_x, stop_y, w.as_str(), colors::TEXT_PRIMARY, None);
    font.draw_string(
        fb,
        margin_x,
        stop_y + 20,
        "100% complete",
        colors::TEXT_SECONDARY,
        None,
    );
}

// ============================================================================
// パニックハンドラ統合用API
// ============================================================================

pub fn show_panic_bsod(info: &BsodInfo) {
    display_bsod(info);
}

pub fn show_double_fault_bsod(
    _stack_frame: &x86_64::structures::idt::InterruptStackFrame,
    error_code: u64,
) {
    let mut msg_buf = [0u8; 128];
    let mut w = StackFmtWriter::new(&mut msg_buf);
    let _ = write!(w, "DOUBLE FAULT: Error code {:#x}", error_code);

    let registers = RegisterDump::capture();

    let info = BsodInfo::new(w.as_str())
        .with_registers(registers)
        .with_error_code("DOUBLE_FAULT");

    dump_bsod_info_to_serial(&info);
    display_bsod(&info);
}
