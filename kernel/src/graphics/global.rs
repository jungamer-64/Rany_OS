// ============================================================================
// src/graphics/global.rs - Global Graphics State
// ============================================================================
//!
//! グローバルグラフィックス状態管理
//!
//! フレームバッファとコンソールのグローバルインスタンス管理

#![allow(dead_code)]

use limine::response::FramebufferResponse;
use spin::Mutex;

use super::console::TextConsole;
use super::framebuffer::Framebuffer;
use super::{Color, FramebufferInfo, PixelFormat};
use crate::memory::physical_memory_offset;
use crate::mm::higher_half::{PageFlags, PageTableManager, VirtAddr};

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
    log::info!("[GRAPHICS] Framebuffer initialized: {}x{}\n", w, h);
}

/// Limineフレームバッファレスポンスからグラフィックスを初期化
///
/// ブートローダーから提供されたフレームバッファ情報を使用して
/// グラフィックスサブシステムを初期化します。
pub fn init_from_limine(response: &FramebufferResponse) -> bool {
    // 最初のフレームバッファを使用
    let mut iter = response.framebuffers();
    let Some(fb) = iter.next() else {
        log::info!("[GRAPHICS] No framebuffer available from bootloader\n");
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

    log::info!(
        "[GRAPHICS] Limine framebuffer: {}x{}@{}bpp pitch={} format={:?}\n",
        info.width,
        info.height,
        info.bpp,
        info.stride,
        info.format
    );

    // Write-Combiningで再マッピング
    // これによりVRAMへの書き込みパフォーマンスが大幅に向上する
    let fb_size = (info.stride as u64) * (info.height as u64);
    remap_framebuffer_wc(info.address, fb_size);

    init(info);
    true
}

/// フレームバッファをWrite-Combiningで再マッピング
///
/// デフォルトのキャッシュ属性（通常はUncacheableまたはWrite-Through）を
/// Write-Combiningに変更して、描画パフォーマンスを向上させる。
fn remap_framebuffer_wc(virt_addr: u64, size: u64) {
    let offset = physical_memory_offset();
    let mut manager = unsafe { PageTableManager::from_current_cr3(offset) };

    // 仮想アドレスと物理アドレスの開始位置を取得
    let virt_start = VirtAddr::new(virt_addr);

    // カーネル空間（Higher Half）にマップされていると仮定して物理アドレスを計算
    // Limineはリニアにマップしてくれているはずだが、念のためtranslateで確認
    let phys_start = if let Some(phys) = manager.translate(virt_start) {
        phys
    } else {
        log::error!(
            "[GRAPHICS] Failed to translate framebuffer virtual address {:#x}\n",
            virt_addr
        );
        return;
    };

    log::info!(
        "[GRAPHICS] Remapping framebuffer: Virt={:#x} Phys={:#x} Size={:#x}\n",
        virt_start.as_u64(),
        phys_start.as_u64(),
        size
    );

    unsafe {
        // 1. 既存のマッピングを範囲解除
        // エラーは無視（一部マップされていない可能性もあるため許容）
        let _ = manager.unmap_range(virt_start, size);

        // 2. Write-Combining属性で範囲マップ
        // map_rangeはアラインメントとサイズに基づいて自動的にHuge Page (2MiB/1GiB)を使用する
        match manager.map_range(virt_start, phys_start, size, PageFlags::write_combining()) {
            Ok(_) => {
                log::info!("[GRAPHICS] Framebuffer remapped successfully with WC attributes\n");
            }
            Err(e) => {
                log::error!("[GRAPHICS] Failed to remap framebuffer: {:?}\n", e);
            }
        }
    }
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
        log::info!("[GRAPHICS] Text console initialized\n");
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
