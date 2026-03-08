// ============================================================================
// src/graphics/global.rs - Global Graphics State
// ============================================================================
//!
//! グローバルグラフィックス状態管理
//!
//! フレームバッファとコンソールのグローバルインスタンス管理

#![allow(dead_code)]

use crate::sync::PoisonLock;

use super::console::TextConsole;
use super::framebuffer::Framebuffer;
use super::{Color, FramebufferInfo, PixelFormat};
use crate::memory::physical_memory_offset;
use crate::mm::virt::higher_half::{PageFlags, PageTableManager, VirtAddr};
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
static FRAMEBUFFER: PoisonLock<Option<Framebuffer>> = PoisonLock::new(None);

/// フレームバッファを初期化
pub fn init(info: FramebufferInfo) {
    let mut fb = unsafe { Framebuffer::new(info) };
    fb.clear(Color::BLACK);

    *FRAMEBUFFER.lock().unwrap_or_else(|e| e.into_inner()) = Some(fb);

    let (w, h) = {
        let guard = FRAMEBUFFER.lock().unwrap_or_else(|e| e.into_inner());
        let fb = guard.as_ref().expect("framebuffer must be initialized");
        (fb.width(), fb.height())
    };
    log::info!("[GRAPHICS] Framebuffer initialized: {}x{}\n", w, h);
}

/// ExoLoader (UEFI) からのフレームバッファ情報を使用してグラフィックスを初期化
pub fn init_from_boot_info(info: &FramebufferInfo, phys_mem_offset: u64) -> bool {
    crate::io::log::early_print("[GFX] init_from_boot_info entry\n");

    let mut final_info = *info;

    if final_info.bpp == 0 {
        let bpp = match final_info.format {
            PixelFormat::Bgra8888 | PixelFormat::Rgba8888 => 32,
            PixelFormat::Rgb888 | PixelFormat::Bgr888 => 24,
            PixelFormat::Rgb565 => 16,
        };
        final_info.bpp = bpp;
    }

    if final_info.stride == final_info.width {
        final_info.stride = final_info.width * (final_info.bpp as u32 / 8);
    }

    let limine_virt_addr = final_info.address;

    let phys_addr = if limine_virt_addr >= phys_mem_offset {
        limine_virt_addr - phys_mem_offset
    } else {
        limine_virt_addr
    };

    crate::io::log::early_print("[GFX] Calculated phys addr\n");

    let hhdm_virt_addr = phys_mem_offset + phys_addr;

    let _ = write!(
        EarlyBuf,
        "[GFX] FB: {}x{} bpp={} pitch={} phys={:#x} hhdm={:#x}\n",
        final_info.width,
        final_info.height,
        final_info.bpp,
        final_info.stride,
        phys_addr,
        hhdm_virt_addr
    );

    let fb_size = (final_info.stride as u64) * (final_info.height as u64);

    crate::io::log::early_print("[GFX] About to call map_framebuffer_vram\n");

    let mapped_virt_addr = {
        let result = map_framebuffer_vram(phys_addr, fb_size, phys_mem_offset);
        if result == 0 {
            crate::io::log::early_print("[GFX] map_range failed, falling back to HHDM address\n");
            log::warn!(
                "[GRAPHICS] Could not remap framebuffer (WC), utilizing HHDM mapping at {:#x}\n",
                hhdm_virt_addr
            );
            hhdm_virt_addr
        } else {
            crate::io::log::early_print("[GFX] map_framebuffer_vram succeeded\n");
            result
        }
    };

    final_info.address = mapped_virt_addr;

    log::info!(
        "[GRAPHICS] Framebuffer: {}x{}@{}bpp pitch={} format={:?} mapped_virt={:#x}\n",
        final_info.width,
        final_info.height,
        final_info.bpp,
        final_info.stride,
        final_info.format,
        final_info.address
    );

    crate::io::log::early_print("[GFX] Calling init(info)\n");
    init(final_info);
    crate::io::log::early_print("[GFX] init_from_boot_info complete\n");
    true
}

fn map_framebuffer_vram(phys_addr: u64, size: u64, offset: u64) -> u64 {
    use crate::mm::virt::higher_half::PhysAddr;

    crate::io::log::early_print("[GFX] map_framebuffer_vram entry\n");

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

    crate::io::log::early_print("[GFX] About to call global_unmap_range and global_map_range\n");

    unsafe {
        let _ = crate::mm::virt::higher_half::global_unmap_range(virt_start, size);
        crate::io::log::early_print("[GFX] Existing mapping cleared\n");

        match crate::mm::virt::higher_half::global_map_range(
            virt_start,
            phys_start,
            size,
            PageFlags::write_combining(),
        ) {
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

fn remap_framebuffer_wc(virt_addr: u64, size: u64) {
    let offset = physical_memory_offset();
    let manager = unsafe { PageTableManager::from_current_cr3(offset) };

    let virt_start = VirtAddr::new(virt_addr);

    let phys_start = if let Some(phys) = manager.translate(virt_start) {
        phys
    } else {
        log::error!(
            "[GRAPHICS] Failed to translate framebuffer virtual address {:#x}\n",
            virt_addr
        );
        return;
    };

    let offset = physical_memory_offset();
    let phys_addr = if virt_addr >= offset {
        virt_addr - offset
    } else {
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
        let _ = crate::mm::virt::higher_half::global_unmap_range(virt_start, size);

        match crate::mm::virt::higher_half::global_map_range(
            virt_start,
            phys_start,
            size,
            PageFlags::write_combining(),
        ) {
            Ok(_) => {
                log::info!("[GRAPHICS] Framebuffer remapped successfully with WC attributes\n");
            }
            Err(e) => {
                log::error!("[GRAPHICS] Failed to remap framebuffer: {:?}\n", e);
            }
        }
    }
}

fn detect_32bpp_format(red_shift: u8, green_shift: u8, blue_shift: u8) -> PixelFormat {
    if red_shift == 16 && green_shift == 8 && blue_shift == 0 {
        PixelFormat::Bgra8888
    } else if red_shift == 0 && green_shift == 8 && blue_shift == 16 {
        PixelFormat::Rgba8888
    } else {
        PixelFormat::Bgra8888
    }
}

fn detect_24bpp_format(red_shift: u8, green_shift: u8, blue_shift: u8) -> PixelFormat {
    if red_shift == 16 && green_shift == 8 && blue_shift == 0 {
        PixelFormat::Bgr888
    } else {
        PixelFormat::Rgb888
    }
}

fn detect_16bpp_format(red_size: u8, green_size: u8, blue_size: u8) -> PixelFormat {
    if red_size == 5 && green_size == 6 && blue_size == 5 {
        PixelFormat::Rgb565
    } else {
        PixelFormat::Rgb565
    }
}

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
        32 => detect_32bpp_format(red_shift, green_shift, blue_shift),
        24 => detect_24bpp_format(red_shift, green_shift, blue_shift),
        16 => detect_16bpp_format(red_size, green_size, blue_size),
        _ => PixelFormat::Bgra8888,
    }
}

/// グラフィカルコンソールを初期化
pub fn init_console() {
    let mut fb_guard = FRAMEBUFFER.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(ref mut fb) = *fb_guard {
        let (console, cols, rows) = TextConsole::new(fb);
        crate::console::init(cols, rows);
        crate::console::set_driver(alloc::boxed::Box::new(console));
        drop(fb_guard);
        log::info!("[GRAPHICS] Text console initialized as driver\n");
    }
}

/// フレームバッファにアクセス
pub fn with_framebuffer<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut Framebuffer) -> R,
{
    let mut guard = FRAMEBUFFER.lock().unwrap_or_else(|e| e.into_inner());
    guard.as_mut().map(f)
}

/// フレームバッファが初期化されているか確認
pub fn framebuffer() -> Option<()> {
    if FRAMEBUFFER.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
        Some(())
    } else {
        None
    }
}

/// コンソールに出力
pub fn console_print(s: &str) {
    crate::console::write(s);
}

/// フレームバッファのロックを強制解除（パニック時用）
pub unsafe fn force_unlock_framebuffer() {
    FRAMEBUFFER.force_unlock();
}
