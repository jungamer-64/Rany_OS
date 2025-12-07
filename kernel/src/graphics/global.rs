// ============================================================================
// src/graphics/global.rs - Global Graphics State
// ============================================================================
//!
//! グローバルグラフィックス状態管理
//!
//! フレームバッファとコンソールのグローバルインスタンス管理

#![allow(dead_code)]

use spin::Mutex;
use limine::response::FramebufferResponse;

use super::types::{Color, FramebufferInfo, PixelFormat};
use super::framebuffer::Framebuffer;
use super::console::TextConsole;

// ============================================================================
// Global State
// ============================================================================

/// グローバルフレームバッファ
static FRAMEBUFFER: Mutex<Option<Framebuffer>> = Mutex::new(None);

/// グローバルコンソール
static CONSOLE: Mutex<Option<TextConsole>> = Mutex::new(None);

/// フレームバッファを初期化
pub fn init(info: FramebufferInfo) {
    let mut fb = unsafe { Framebuffer::new(info) };
    fb.clear(Color::BLACK);

    *FRAMEBUFFER.lock() = Some(fb);

    // ロックを1回だけ取得して情報を取り出す（2回のlock+unwrap → 1回のlockで変数コピー）
    // アセンブリ: 2x (lock acquire + memory fence + unwrap check) → 1x lock + 2x mov
    let (w, h) = {
        let guard = FRAMEBUFFER.lock();
        let fb = guard.as_ref().expect("framebuffer must be initialized");
        (fb.width(), fb.height())
    };
    crate::log!("[GRAPHICS] Framebuffer initialized: {}x{}\n", w, h);
}

/// Limineフレームバッファレスポンスからグラフィックスを初期化
/// 
/// ブートローダーから提供されたフレームバッファ情報を使用して
/// グラフィックスサブシステムを初期化します。
pub fn init_from_limine(response: &FramebufferResponse) -> bool {
    // 最初のフレームバッファを使用
    let mut iter = response.framebuffers();
    let Some(fb) = iter.next() else {
        crate::log!("[GRAPHICS] No framebuffer available from bootloader\n");
        return false;
    };

    // ピクセルフォーマットを判定
    // Limineは通常BGRA8888フォーマットを使用
    let format = detect_pixel_format(
        fb.red_mask_size(),
        fb.red_mask_shift(),
        fb.green_mask_size(),
        fb.green_mask_shift(),
        fb.blue_mask_size(),
        fb.blue_mask_shift(),
        fb.bpp(),
    );

    let info = FramebufferInfo {
        address: fb.addr() as u64,
        width: fb.width() as u32,
        height: fb.height() as u32,
        stride: fb.pitch() as u32,
        format,
        bpp: fb.bpp() as u8,
    };

    crate::log!(
        "[GRAPHICS] Limine framebuffer: {}x{}@{}bpp pitch={} format={:?}\n",
        info.width,
        info.height,
        info.bpp,
        info.stride,
        info.format
    );

    init(info);
    true
}

/// マスク情報からピクセルフォーマットを判定
fn detect_pixel_format(
    red_size: u8,
    red_shift: u8,
    green_size: u8,
    green_shift: u8,
    blue_size: u8,
    blue_shift: u8,
    bpp: u16,
) -> PixelFormat {
    match bpp {
        32 => {
            // 32bpp: BGRA or RGBA
            if red_shift == 16 && green_shift == 8 && blue_shift == 0 {
                PixelFormat::Bgra8888
            } else if red_shift == 0 && green_shift == 8 && blue_shift == 16 {
                PixelFormat::Rgba8888
            } else {
                // デフォルトはBGRA（最も一般的）
                PixelFormat::Bgra8888
            }
        }
        24 => {
            // 24bpp: BGR or RGB
            if red_shift == 16 && green_shift == 8 && blue_shift == 0 {
                PixelFormat::Bgr888
            } else {
                PixelFormat::Rgb888
            }
        }
        16 => {
            // 16bpp: RGB565
            if red_size == 5 && green_size == 6 && blue_size == 5 {
                PixelFormat::Rgb565
            } else {
                PixelFormat::Rgb565 // デフォルト
            }
        }
        _ => PixelFormat::Bgra8888, // 未知のフォーマットはBGRA8888を仮定
    }
}

/// グラフィカルコンソールを初期化
pub fn init_console() {
    let mut fb_guard = FRAMEBUFFER.lock();
    if let Some(ref mut fb) = *fb_guard {
        let console = TextConsole::new(fb);
        drop(fb_guard);
        *CONSOLE.lock() = Some(console);
        crate::log!("[GRAPHICS] Text console initialized\n");
    }
}

/// フレームバッファにアクセス
pub fn with_framebuffer<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut Framebuffer) -> R,
{
    let mut guard = FRAMEBUFFER.lock();
    guard.as_mut().map(f)
}

/// コンソールにアクセス
pub fn with_console<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut TextConsole) -> R,
{
    let mut guard = CONSOLE.lock();
    guard.as_mut().map(f)
}

/// フレームバッファが初期化されているか確認
pub fn framebuffer() -> Option<()> {
    if FRAMEBUFFER.lock().is_some() {
        Some(())
    } else {
        None
    }
}

/// コンソールに出力
pub fn console_print(s: &str) {
    with_console(|console| {
        console.write_str(s);
    });
}
