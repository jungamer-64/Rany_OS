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
use core::fmt::{self, Write};

// Simple buffer for formatting - safe enough for single threaded boot
struct EarlyBuf;
impl Write for EarlyBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        crate::io::log::early_print(s);
        Ok(())
    }
}

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
    crate::io::log::early_print("[GFX] init_from_limine entry\n");

    // 最初のフレームバッファを使用
    let mut iter = response.framebuffers();
    let Some(fb) = iter.next() else {
        crate::io::log::early_print("[GFX] No framebuffer available\n");
        log::info!("[GRAPHICS] No framebuffer available from bootloader\n");
        return false;
    };

    crate::io::log::early_print("[GFX] Got framebuffer from iterator\n");

    // Limine provides a virtual address via fb.addr(), but this is calculated as
    // HHDM_OFFSET + physical_address. However, Limine's HHDM only maps RAM, not MMIO/VRAM.
    // For framebuffers at physical addresses like 0x80000000 (2GB), we must explicitly map them.

    let limine_virt_addr = fb.addr() as u64;
    let hhdm_offset = physical_memory_offset();

    // Calculate physical address from Limine's HHDM-based virtual address
    let phys_addr = if limine_virt_addr >= hhdm_offset {
        limine_virt_addr - hhdm_offset
    } else {
        // Fallback: assume it's already a physical address
        limine_virt_addr
    };

    crate::io::log::early_print("[GFX] Calculated phys addr\n");

    let _ = write!(
        EarlyBuf,
        "[GFX] Framebuffer: limine_virt={:#x} hhdm={:#x} phys={:#x}\n",
        limine_virt_addr, hhdm_offset, phys_addr
    );

    // ピクセルフォーマットを判定
    // Limineは通常BGRA8888フォーマットを使用
    let bpp = fb.bpp();
    let red_mask_size = fb.red_mask_size();
    let red_mask_shift = fb.red_mask_shift();
    let green_mask_size = fb.green_mask_size();
    let green_mask_shift = fb.green_mask_shift();
    let blue_mask_size = fb.blue_mask_size();
    let blue_mask_shift = fb.blue_mask_shift();

    let _ = write!(
        EarlyBuf,
        "[GFX] FB: {}x{} bpp={} pitch={}\n",
        fb.width(),
        fb.height(),
        bpp,
        fb.pitch()
    );
    let _ = write!(
        EarlyBuf,
        "[GFX] Masks: R={}:{} G={}:{} B={}:{}\n",
        red_mask_size,
        red_mask_shift,
        green_mask_size,
        green_mask_shift,
        blue_mask_size,
        blue_mask_shift
    );

    let format = detect_pixel_format(
        red_mask_size,
        red_mask_shift,
        green_mask_size,
        green_mask_shift,
        blue_mask_size,
        blue_mask_shift,
        bpp as u16,
    );
    let _ = write!(EarlyBuf, "[GFX] Detected Format: {:?}\n", format);

    let fb_size = (fb.pitch() as u64) * (fb.height() as u64);

    crate::io::log::early_print("[GFX] About to call map_framebuffer_vram\n");

    // Try to explicitly map the framebuffer with Write-Combining attributes
    // If this fails (e.g., because Limine already mapped it), fall back to Limine's address
    let mapped_virt_addr = {
        let result = map_framebuffer_vram(phys_addr, fb_size);
        if result == 0 {
            crate::io::log::early_print("[GFX] map_range failed, using Limine's address\n");
            log::warn!(
                "[GRAPHICS] Could not remap framebuffer, using Limine's mapping at {:#x}\n",
                limine_virt_addr
            );
            // Use Limine's original address - it should be mapped by the bootloader
            limine_virt_addr
        } else {
            crate::io::log::early_print("[GFX] map_framebuffer_vram succeeded\n");
            result
        }
    };

    let info = FramebufferInfo {
        address: mapped_virt_addr, // Use our explicitly mapped address or Limine's
        width: fb.width() as u32,
        height: fb.height() as u32,
        stride: fb.pitch() as u32,
        format,
        bpp: fb.bpp() as u8,
    };

    log::info!(
        "[GRAPHICS] Limine framebuffer: {}x{}@{}bpp pitch={} format={:?} mapped_virt={:#x}\n",
        info.width,
        info.height,
        info.bpp,
        info.stride,
        info.format,
        mapped_virt_addr
    );

    crate::io::log::early_print("[GFX] Calling init(info)\n");
    init(info);
    crate::io::log::early_print("[GFX] init_from_limine complete\n");
    true
}

/// Map framebuffer VRAM to kernel virtual address space with Write-Combining attributes
///
/// Returns the virtual address where the framebuffer is mapped, or 0 on failure.
fn map_framebuffer_vram(phys_addr: u64, size: u64) -> u64 {
    use crate::mm::higher_half::PhysAddr;

    crate::io::log::early_print("[GFX] map_framebuffer_vram entry\n");

    let offset = physical_memory_offset();
    let mut manager = unsafe { PageTableManager::from_current_cr3(offset) };

    // Use a dedicated virtual address range for MMIO mappings
    // We'll use HHDM_OFFSET + phys_addr but explicitly map it
    let virt_addr = offset + phys_addr;
    let virt_start = VirtAddr::new(virt_addr);
    let phys_start = PhysAddr::new(phys_addr);

    let _ = write!(
        EarlyBuf,
        "[GFX] Mapping framebuffer: Virt={:#x} Phys={:#x} Size={:#x}\n",
        virt_start.as_u64(),
        phys_start.as_u64(),
        size
    );

    crate::io::log::early_print("[GFX] About to call map_range\n");

    unsafe {
        // Map with Write-Combining attributes for optimal VRAM performance
        match manager.map_range(virt_start, phys_start, size, PageFlags::write_combining()) {
            Ok(_) => {
                crate::io::log::early_print("[GFX] map_range OK\n");
                log::info!("[GRAPHICS] Framebuffer mapped successfully with WC attributes\n");
                virt_addr
            }
            Err(e) => {
                crate::io::log::early_print("[GFX] map_range FAILED\n");
                log::error!("[GRAPHICS] Failed to map framebuffer: {:?}\n", e);
                0
            }
        }
    }
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

    // 物理アドレスを逆算（HHDMオフセットを引く）
    // オフセットが設定されていない場合は、Limineが提供する物理アドレス取得手段がないため
    // 仮想アドレスからオフセットを引いて計算する
    let offset = physical_memory_offset();
    let phys_addr = if virt_addr >= offset {
        virt_addr - offset
    } else {
        // HHDM外？
        virt_addr
    };

    use crate::io::log::early_print;
    use core::fmt::Write;
    struct EarlyBuf;
    impl Write for EarlyBuf {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            early_print(s);
            Ok(())
        }
    }

    let _ = write!(EarlyBuf, "[GFX] Limine Virt: {:#x}\n", virt_addr);
    let _ = write!(EarlyBuf, "[GFX] Offset: {:#x}\n", offset);
    let _ = write!(EarlyBuf, "[GFX] Calc Phys: {:#x}\n", phys_addr);

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
