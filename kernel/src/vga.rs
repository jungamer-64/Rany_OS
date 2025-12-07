// ============================================================================
// src/vga.rs - VGA Text Mode Output (for logging)
// ============================================================================
use core::fmt;
use spin::Mutex;

const BUFFER_HEIGHT: usize = 25;
const BUFFER_WIDTH: usize = 80;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Color {
    Black = 0,
    Blue = 1,
    Green = 2,
    Cyan = 3,
    Red = 4,
    Magenta = 5,
    Brown = 6,
    LightGray = 7,
    DarkGray = 8,
    LightBlue = 9,
    LightGreen = 10,
    LightCyan = 11,
    LightRed = 12,
    Pink = 13,
    Yellow = 14,
    White = 15,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
struct ColorCode(u8);

impl ColorCode {
    const fn new(foreground: Color, background: Color) -> ColorCode {
        ColorCode((background as u8) << 4 | (foreground as u8))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
struct ScreenChar {
    ascii_character: u8,
    color_code: ColorCode,
}

#[repr(transparent)]
struct Buffer {
    chars: [[ScreenChar; BUFFER_WIDTH]; BUFFER_HEIGHT],
}

pub struct Writer {
    column_position: usize,
    color_code: ColorCode,
    buffer: *mut Buffer,
}

impl Writer {
    pub fn write_byte(&mut self, byte: u8) {
        match byte {
            b'\n' => self.new_line(),
            byte => {
                if self.column_position >= BUFFER_WIDTH {
                    self.new_line();
                }

                let row = BUFFER_HEIGHT - 1;
                let col = self.column_position;

                let color_code = self.color_code;
                unsafe {
                    core::ptr::write_volatile(
                        &mut (*self.buffer).chars[row][col],
                        ScreenChar {
                            ascii_character: byte,
                            color_code,
                        },
                    );
                }
                self.column_position += 1;
            }
        }
    }

    pub fn write_string(&mut self, s: &str) {
        for byte in s.bytes() {
            match byte {
                0x20..=0x7e | b'\n' => self.write_byte(byte),
                _ => self.write_byte(0xfe), // ■
            }
        }
    }

    fn new_line(&mut self) {
        for row in 1..BUFFER_HEIGHT {
            for col in 0..BUFFER_WIDTH {
                unsafe {
                    let character = core::ptr::read_volatile(&(*self.buffer).chars[row][col]);
                    core::ptr::write_volatile(&mut (*self.buffer).chars[row - 1][col], character);
                }
            }
        }
        self.clear_row(BUFFER_HEIGHT - 1);
        self.column_position = 0;
    }

    fn clear_row(&mut self, row: usize) {
        let blank = ScreenChar {
            ascii_character: b' ',
            color_code: self.color_code,
        };
        for col in 0..BUFFER_WIDTH {
            unsafe {
                core::ptr::write_volatile(&mut (*self.buffer).chars[row][col], blank);
            }
        }
    }
}

impl fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_string(s);
        Ok(())
    }
}

// SAFETY: VGA バッファは固定アドレスにあり、Writerは単一スレッドでのみ使用される
unsafe impl Send for Writer {}

static WRITER: Mutex<Writer> = Mutex::new(Writer {
    column_position: 0,
    color_code: ColorCode::new(Color::Yellow, Color::Black),
    buffer: 0xb8000 as *mut Buffer,
});

static VGA_AVAILABLE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn init() {
    // UEFI環境ではVGAテキストモードバッファは使用不可
    // Limineのフレームバッファを使用する場合は別途初期化が必要
    // 今のところはVGAを無効にしておく
    
    // 簡易チェック: 0xb8000がマップされているかテスト
    // UEFI環境ではこのアドレスは通常マップされていない
    #[cfg(not(feature = "force_vga"))]
    {
        // VGAバッファをクリアしない（UEFIでは無効なアドレス）
        // 代わりにシリアル出力のみを使用
        VGA_AVAILABLE.store(false, core::sync::atomic::Ordering::Release);
    }
    
    #[cfg(feature = "force_vga")]
    {
        VGA_AVAILABLE.store(true, core::sync::atomic::Ordering::Release);
        WRITER.lock().clear_row(BUFFER_HEIGHT - 1);
    }
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use core::fmt::Write;
    
    // VGAが利用可能な場合のみ書き込み
    if VGA_AVAILABLE.load(core::sync::atomic::Ordering::Acquire) {
        let _ = WRITER.lock().write_fmt(args);
    }
    // それ以外の場合はシリアル出力を使用（io::logが処理）
}

/// 早期ブート段階用のシリアル出力（ロックなし、シンプル）
/// 
/// 注意: この関数は後方互換性のために残されています。
/// 新規コードでは `io::log::early_print` または `log` クレートを使用してください。
pub fn early_serial_char(c: u8) {
    crate::io::log::early_print_char(c);
}

/// 早期ブート段階用のシリアル文字列出力
/// 
/// 注意: この関数は後方互換性のために残されています。
/// 新規コードでは `io::log::early_print` または `log` クレートを使用してください。
pub fn early_serial_str(s: &str) {
    crate::io::log::early_print(s);
}

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => ({
        $crate::vga::_print(format_args!($($arg)*));
        // 早期ブート段階ではシンプルなシリアル出力を使用
        // format_args!を直接使うのは複雑なので、一旦VGAのみ
    });
}

/// VGAとシリアル両方に出力するマクロ（シリアル初期化後用）
#[macro_export]
macro_rules! log_serial {
    ($($arg:tt)*) => ({
        $crate::vga::_print(format_args!($($arg)*));
        $crate::io::serial::_print(format_args!($($arg)*));
    });
}
