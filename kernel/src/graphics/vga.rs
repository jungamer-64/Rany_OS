// ============================================================================
// src/graphics/vga.rs - VGA Text Mode Output (for logging)
//
// 以前は src/vga.rs にルートレベルで配置されていたが、
// グラフィックス出力の一形態であるため graphics/ モジュール配下に移動。
// ============================================================================
use crate::sync::PoisonLock;
use core::fmt;

const BUFFER_HEIGHT: usize = 25;
const BUFFER_WIDTH: usize = 80;

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

pub struct Writer {
    column_position: usize,
    color_code: ColorCode,
    buffer: hal::MappedMmio,
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
                Self::write_char_volatile(
                    &self.buffer,
                    row,
                    col,
                    ScreenChar {
                        ascii_character: byte,
                        color_code,
                    },
                );
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
                let character = Self::read_char_volatile(&self.buffer, row, col);
                Self::write_char_volatile(&self.buffer, row - 1, col, character);
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
            Self::write_char_volatile(&self.buffer, row, col, blank);
        }
    }

    fn write_char_volatile(
        buffer: &hal::MappedMmio,
        row: usize,
        column: usize,
        character: ScreenChar,
    ) {
        let offset = (row * BUFFER_WIDTH + column) * 2;
        let value = u16::from_le_bytes([character.ascii_character, character.color_code.0]);
        buffer
            .region()
            .write_only::<u16>(offset)
            .expect("text cell in retained VGA aperture")
            .write(value);
    }
    fn read_char_volatile(buffer: &hal::MappedMmio, row: usize, column: usize) -> ScreenChar {
        let offset = (row * BUFFER_WIDTH + column) * 2;
        let bytes = buffer
            .region()
            .read_only::<u16>(offset)
            .expect("text cell in retained VGA aperture")
            .read()
            .to_le_bytes();
        ScreenChar {
            ascii_character: bytes[0],
            color_code: ColorCode(bytes[1]),
        }
    }
}

impl fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_string(s);
        Ok(())
    }
}

static WRITER: PoisonLock<Option<Writer>> = PoisonLock::new(None);

static VGA_AVAILABLE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn init() {
    #[cfg(feature = "force_vga")]
    {
        match crate::resource_registry::mmio::acquire_vga_text() {
            Ok(buffer) => {
                let mut writer = Writer {
                    column_position: 0,
                    color_code: ColorCode::new(Color::Yellow, Color::Black),
                    buffer,
                };
                writer.clear_row(BUFFER_HEIGHT - 1);
                *WRITER.lock().unwrap_or_else(|error| error.into_inner()) = Some(writer);
                VGA_AVAILABLE.store(true, core::sync::atomic::Ordering::Release);
            }
            Err(error) => log::warn!("VGA text aperture unavailable: {:?}", error),
        }
    }
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use core::fmt::Write;

    // VGAが利用可能な場合のみ書き込み
    if VGA_AVAILABLE.load(core::sync::atomic::Ordering::Acquire) {
        if let Some(writer) = WRITER
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_mut()
        {
            // fmt writes into this retained device and cannot fail after admission.
            if writer.write_fmt(args).is_err() {
                return;
            }
        }
    }
    // それ以外の場合はシリアル出力を使用（io::logが処理）
}
