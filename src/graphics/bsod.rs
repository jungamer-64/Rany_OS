// ============================================================================
// src/graphics/bsod.rs - Blue Screen of Death Display
// ============================================================================
//!
//! # BSOD (Blue Screen of Death) 表示モジュール
//!
//! カーネルパニック発生時に画面全体を青く塗りつぶし、
//! エラー詳細、スタックトレース、レジスタダンプ、QRコードを表示する。
//!
//! ## 機能
//! - 画面全体の青色塗りつぶし
//! - エラーメッセージと場所の表示
//! - スタックトレースの表示
//! - CPUレジスタダンプの表示
//! - エラーコードのQRコード表示

#![allow(dead_code)]

use alloc::string::String;
use alloc::format;
use core::fmt::Write;

use super::{Color, Framebuffer, Rect, with_framebuffer, BitmapFont};
use super::qrcode::QrCode;
use crate::unwind::{Backtrace, StackFrame};

// ============================================================================
// BSOD カラーパレット
// ============================================================================

/// BSOD用カラー定義
pub mod colors {
    use super::Color;

    /// 背景色（Windows風の青）
    pub const BACKGROUND: Color = Color::new(0x00, 0x78, 0xD7);

    /// 悲しい顔のカラー
    pub const SAD_FACE: Color = Color::new(0xFF, 0xFF, 0xFF);

    /// メインテキストカラー
    pub const TEXT_PRIMARY: Color = Color::new(0xFF, 0xFF, 0xFF);

    /// セカンダリテキストカラー
    pub const TEXT_SECONDARY: Color = Color::new(0xCC, 0xCC, 0xCC);

    /// エラーコードカラー
    pub const ERROR_CODE: Color = Color::new(0xFF, 0xFF, 0x00);

    /// 区切り線カラー
    pub const SEPARATOR: Color = Color::new(0x40, 0x90, 0xE0);

    /// QRコード背景
    pub const QR_LIGHT: Color = Color::new(0xFF, 0xFF, 0xFF);

    /// QRコードモジュール
    pub const QR_DARK: Color = Color::new(0x00, 0x00, 0x00);
}

// ============================================================================
// BSOD情報構造体
// ============================================================================

/// BSOD表示用のエラー情報
pub struct BsodInfo {
    /// エラーメッセージ
    pub message: String,
    /// エラー発生ファイル
    pub file: Option<String>,
    /// エラー発生行
    pub line: Option<u32>,
    /// エラー発生カラム
    pub column: Option<u32>,
    /// スタックトレース
    pub backtrace: Option<Backtrace>,
    /// レジスタダンプ
    pub registers: Option<RegisterDump>,
    /// エラーコード（QRコード用）
    pub error_code: String,
}

impl BsodInfo {
    /// 新しいBSOD情報を作成
    pub fn new(message: &str) -> Self {
        Self {
            message: String::from(message),
            file: None,
            line: None,
            column: None,
            backtrace: None,
            registers: None,
            error_code: String::from("KERNEL_PANIC"),
        }
    }

    /// ファイル情報を設定
    pub fn with_location(mut self, file: &str, line: u32, column: u32) -> Self {
        self.file = Some(String::from(file));
        self.line = Some(line);
        self.column = Some(column);
        self
    }

    /// スタックトレースを設定
    pub fn with_backtrace(mut self, backtrace: Backtrace) -> Self {
        self.backtrace = Some(backtrace);
        self
    }

    /// レジスタダンプを設定
    pub fn with_registers(mut self, registers: RegisterDump) -> Self {
        self.registers = Some(registers);
        self
    }

    /// エラーコードを設定
    pub fn with_error_code(mut self, code: &str) -> Self {
        self.error_code = String::from(code);
        self
    }
}

/// CPUレジスタダンプ
#[derive(Clone, Debug)]
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
    /// 現在のレジスタ状態をキャプチャ
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
                "mov {rax}, rax",
                "mov {rbx}, rbx",
                "mov {rcx}, rcx",
                "mov {rdx}, rdx",
                rax = out(reg) rax,
                rbx = out(reg) rbx,
                rcx = out(reg) rcx,
                rdx = out(reg) rdx,
                options(nostack, preserves_flags)
            );

            core::arch::asm!(
                "mov {rsi}, rsi",
                "mov {rdi}, rdi",
                "mov {rbp}, rbp",
                "mov {rsp}, rsp",
                rsi = out(reg) rsi,
                rdi = out(reg) rdi,
                rbp = out(reg) rbp,
                rsp = out(reg) rsp,
                options(nostack, preserves_flags)
            );

            core::arch::asm!(
                "mov {r8}, r8",
                "mov {r9}, r9",
                "mov {r10}, r10",
                "mov {r11}, r11",
                r8 = out(reg) r8,
                r9 = out(reg) r9,
                r10 = out(reg) r10,
                r11 = out(reg) r11,
                options(nostack, preserves_flags)
            );

            core::arch::asm!(
                "mov {r12}, r12",
                "mov {r13}, r13",
                "mov {r14}, r14",
                "mov {r15}, r15",
                r12 = out(reg) r12,
                r13 = out(reg) r13,
                r14 = out(reg) r14,
                r15 = out(reg) r15,
                options(nostack, preserves_flags)
            );

            core::arch::asm!(
                "pushfq",
                "pop {rflags}",
                rflags = out(reg) rflags,
                options(preserves_flags)
            );

            core::arch::asm!(
                "mov {cr0}, cr0",
                "mov {cr2}, cr2",
                "mov {cr3}, cr3",
                "mov {cr4}, cr4",
                cr0 = out(reg) cr0,
                cr2 = out(reg) cr2,
                cr3 = out(reg) cr3,
                cr4 = out(reg) cr4,
                options(nostack, preserves_flags)
            );
        }

        // RIPは現在の関数アドレスを取得
        let rip: u64;
        unsafe {
            core::arch::asm!(
                "lea {rip}, [rip]",
                rip = out(reg) rip,
                options(nostack, preserves_flags)
            );
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
// BSOD描画関数
// ============================================================================

/// 悲しい顔を描画
fn draw_sad_face(fb: &mut Framebuffer, x: i32, y: i32, scale: u32) {
    let color = colors::SAD_FACE;

    // 顔の輪郭（円）- 簡易版
    let radius = (scale * 30) as i32;
    fb.draw_circle(x + radius, y + radius, radius, color);
    fb.draw_circle(x + radius, y + radius, radius - 1, color);
    fb.draw_circle(x + radius, y + radius, radius - 2, color);

    // 左目
    let eye_y = y + (scale * 20) as i32;
    let left_eye_x = x + (scale * 18) as i32;
    let right_eye_x = x + (scale * 42) as i32;
    fb.fill_rect(Rect::new(left_eye_x, eye_y, scale * 4, scale * 4), color);
    fb.fill_rect(Rect::new(right_eye_x, eye_y, scale * 4, scale * 4), color);

    // 悲しい口（下向きの弧）
    let mouth_y = y + (scale * 40) as i32;
    let mouth_x = x + (scale * 15) as i32;
    for i in 0..(scale * 30) as i32 {
        let offset = (((i - (scale * 15) as i32).pow(2)) / (scale * 8) as i32).min(5);
        fb.set_pixel(mouth_x + i, mouth_y + offset, color);
        fb.set_pixel(mouth_x + i, mouth_y + offset + 1, color);
    }
}

/// セクションヘッダーを描画
fn draw_section_header(fb: &mut Framebuffer, x: i32, y: i32, title: &str, width: u32) {
    let font = BitmapFont::default_8x16();

    // 区切り線
    fb.fill_rect(Rect::new(x, y, width, 2), colors::SEPARATOR);

    // タイトル
    font.draw_string(fb, x, y + 6, title, colors::TEXT_PRIMARY, None);
}

/// レジスタを描画
fn draw_register(fb: &mut Framebuffer, x: i32, y: i32, name: &str, value: u64) {
    let font = BitmapFont::default_8x16();
    let mut buf = String::new();
    let _ = write!(buf, "{:<4} = {:#018x}", name, value);
    font.draw_string(fb, x, y, &buf, colors::TEXT_SECONDARY, None);
}

/// BSODを表示するメイン関数
pub fn display_bsod(info: &BsodInfo) {
    // フレームバッファをロックして直接描画
    // パニック時なので他のロックは気にしない
    with_framebuffer(|fb| {
        display_bsod_internal(fb, info);
    });
}

/// フレームバッファを直接受け取るBSOD表示（パニック時用）
pub fn display_bsod_direct(fb: &mut Framebuffer, info: &BsodInfo) {
    display_bsod_internal(fb, info);
}

/// BSOD表示の内部実装
fn display_bsod_internal(fb: &mut Framebuffer, info: &BsodInfo) {
    let width = fb.width();
    let height = fb.height();
    let font = BitmapFont::default_8x16();

    // 1. 背景を青く塗りつぶす
    fb.clear(colors::BACKGROUND);

    // 2. マージンとレイアウト計算
    let margin_x = (width / 20).max(40) as i32;
    let margin_y = (height / 15).max(30) as i32;
    let content_width = width - (margin_x as u32 * 2);

    let mut y = margin_y;

    // 3. 悲しい顔を描画
    let face_scale = (width / 400).max(1).min(3);
    draw_sad_face(fb, margin_x, y, face_scale);

    // 4. メインメッセージ
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

    // 5. エラーコードセクション
    draw_section_header(fb, margin_x, y, "[ ERROR ]", content_width);
    y += 30;

    // エラーメッセージ
    let msg_lines = wrap_text(&info.message, (content_width / 8) as usize);
    for line in msg_lines.iter().take(3) {
        font.draw_string(fb, margin_x, y, line, colors::ERROR_CODE, None);
        y += 18;
    }

    // 場所情報
    if let (Some(file), Some(line), Some(col)) = (&info.file, info.line, info.column) {
        let mut loc = String::new();
        let _ = write!(loc, "at {}:{}:{}", file, line, col);
        font.draw_string(fb, margin_x, y, &loc, colors::TEXT_SECONDARY, None);
        y += 18;
    }

    y += 10;

    // 6. スタックトレースセクション
    draw_section_header(fb, margin_x, y, "[ STACK TRACE ]", content_width);
    y += 30;

    if let Some(ref bt) = info.backtrace {
        let max_frames = ((height as i32 - y - 200) / 18).max(3).min(10) as usize;
        for entry in bt.iter().take(max_frames) {
            let mut frame_str = String::new();
            let _ = write!(
                frame_str,
                "#{:2} {:#018x} (SP: {:#018x})",
                entry.frame_number,
                entry.frame.instruction_pointer,
                entry.frame.stack_pointer
            );
            font.draw_string(fb, margin_x, y, &frame_str, colors::TEXT_SECONDARY, None);
            y += 18;
        }
        if bt.len() > max_frames {
            let mut more = String::new();
            let _ = write!(more, "    ... and {} more frames", bt.len() - max_frames);
            font.draw_string(fb, margin_x, y, &more, colors::TEXT_SECONDARY, None);
            y += 18;
        }
    } else {
        font.draw_string(fb, margin_x, y, "  (no backtrace available)", colors::TEXT_SECONDARY, None);
        y += 18;
    }

    y += 10;

    // 7. レジスタダンプセクション
    draw_section_header(fb, margin_x, y, "[ REGISTERS ]", content_width);
    y += 30;

    if let Some(ref regs) = info.registers {
        let col_width = (content_width / 3) as i32;

        // 汎用レジスタ（3列）
        let regs_row1 = [
            ("RAX", regs.rax),
            ("RBX", regs.rbx),
            ("RCX", regs.rcx),
        ];
        let regs_row2 = [
            ("RDX", regs.rdx),
            ("RSI", regs.rsi),
            ("RDI", regs.rdi),
        ];
        let regs_row3 = [
            ("RBP", regs.rbp),
            ("RSP", regs.rsp),
            ("RIP", regs.rip),
        ];
        let regs_row4 = [
            ("R8 ", regs.r8),
            ("R9 ", regs.r9),
            ("R10", regs.r10),
        ];
        let regs_row5 = [
            ("R11", regs.r11),
            ("R12", regs.r12),
            ("R13", regs.r13),
        ];
        let regs_row6 = [
            ("R14", regs.r14),
            ("R15", regs.r15),
            ("FLG", regs.rflags),
        ];

        for (i, row) in [regs_row1, regs_row2, regs_row3, regs_row4, regs_row5, regs_row6].iter().enumerate() {
            for (j, (name, value)) in row.iter().enumerate() {
                draw_register(fb, margin_x + (j as i32 * col_width), y, name, *value);
            }
            y += 18;
            // 最大4行まで表示（スペース節約）
            if i >= 3 {
                break;
            }
        }

        // 制御レジスタ
        y += 5;
        let cr_row = [
            ("CR0", regs.cr0),
            ("CR2", regs.cr2),
            ("CR3", regs.cr3),
        ];
        for (j, (name, value)) in cr_row.iter().enumerate() {
            draw_register(fb, margin_x + (j as i32 * col_width), y, name, *value);
        }
        y += 18;
    } else {
        font.draw_string(fb, margin_x, y, "  (registers not captured)", colors::TEXT_SECONDARY, None);
        y += 18;
    }

    // 8. QRコードを右下に描画
    let qr_module_size = (width / 200).max(2).min(4);
    let qr_total_size = (21 + 4) * qr_module_size; // QRサイズ + クワイエットゾーン
    let qr_x = (width - qr_total_size - margin_x as u32) as i32;
    let qr_y = (height - qr_total_size - margin_y as u32) as i32;

    // QRコード生成と描画
    if let Some(qr) = QrCode::new(&info.error_code.to_ascii_uppercase()) {
        qr.draw(
            fb,
            qr_x,
            qr_y,
            qr_module_size,
            colors::QR_DARK,
            colors::QR_LIGHT,
        );

        // QRコードの説明
        font.draw_string(
            fb,
            qr_x,
            qr_y - 20,
            "Scan for more info:",
            colors::TEXT_SECONDARY,
            None,
        );
    }

    // 9. 停止コード
    let stop_y = (height - margin_y as u32 - 40) as i32;
    let mut stop_code = String::new();
    let _ = write!(stop_code, "Stop code: {}", info.error_code);
    font.draw_string(fb, margin_x, stop_y, &stop_code, colors::TEXT_PRIMARY, None);

    // 10. 進捗インジケータ（アニメーションは無理だが、静的に表示）
    font.draw_string(
        fb,
        margin_x,
        stop_y + 20,
        "100% complete",
        colors::TEXT_SECONDARY,
        None,
    );
}

/// テキストを指定幅で折り返す
fn wrap_text(text: &str, max_width: usize) -> alloc::vec::Vec<String> {
    let mut lines = alloc::vec::Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.len() + word.len() + 1 > max_width {
            if !current_line.is_empty() {
                lines.push(current_line);
                current_line = String::new();
            }
        }
        if !current_line.is_empty() {
            current_line.push(' ');
        }
        current_line.push_str(word);
    }

    if !current_line.is_empty() {
        lines.push(current_line);
    }

    lines
}

// ============================================================================
// パニックハンドラ統合用API
// ============================================================================

/// パニック情報からBSODを表示
/// 
/// パニックハンドラから呼び出されることを想定
pub fn show_panic_bsod(
    message: &str,
    file: Option<&str>,
    line: Option<u32>,
    column: Option<u32>,
) {
    // レジスタをキャプチャ
    let registers = RegisterDump::capture();

    // スタックトレースをキャプチャ
    let backtrace = Backtrace::capture();

    // エラーコード生成（簡略化）
    let error_code = generate_error_code(message);

    // BSOD情報を構築
    let mut info = BsodInfo::new(message);

    if let (Some(f), Some(l), Some(c)) = (file, line, column) {
        info = info.with_location(f, l, c);
    }

    info = info
        .with_backtrace(backtrace)
        .with_registers(registers)
        .with_error_code(&error_code);

    // BSODを表示
    display_bsod(&info);
}

/// メッセージからエラーコードを生成
fn generate_error_code(message: &str) -> String {
    // メッセージの最初の単語を取得してエラーコードに変換
    let first_word = message
        .split_whitespace()
        .next()
        .unwrap_or("UNKNOWN");

    // 簡単なハッシュでコードを生成
    let hash: u32 = first_word.bytes().fold(0u32, |acc, b| {
        acc.wrapping_mul(31).wrapping_add(b as u32)
    });

    format!("0x{:08X}", hash)
}

/// Double Fault用のBSOD表示
pub fn show_double_fault_bsod(
    stack_frame: &x86_64::structures::idt::InterruptStackFrame,
    error_code: u64,
) {
    let message = format!(
        "DOUBLE FAULT: Error code {:#x}",
        error_code
    );

    let registers = RegisterDump::capture();

    let mut info = BsodInfo::new(&message);
    info = info
        .with_registers(registers)
        .with_error_code("DOUBLE_FAULT");

    // スタックフレーム情報を追加
    let mut extended_msg = String::new();
    let _ = write!(
        extended_msg,
        "{}\nRIP: {:#018x}\nRSP: {:#018x}\nRFLAGS: {:#018x}",
        message,
        stack_frame.instruction_pointer.as_u64(),
        stack_frame.stack_pointer.as_u64(),
        stack_frame.cpu_flags
    );
    info.message = extended_msg;

    display_bsod(&info);
}
