// ============================================================================
// src/graphics/global.rs - Global Graphics State
// ============================================================================
//!
//! グローバルグラフィックス状態管理
//!
//! フレームバッファとコンソールのグローバルインスタンス管理
use crate::sync::PoisonLock;

use super::console::TextConsole;
use super::framebuffer::Framebuffer;
use super::{Color, framebuffer::PixelBuffer};

static FRAMEBUFFER: PoisonLock<Option<Framebuffer>> = PoisonLock::new(None);

#[derive(Debug)]
pub(crate) enum FramebufferInitError {
    Resource(crate::resource_registry::mmio::BootScanoutError),
    Framebuffer(super::framebuffer::FramebufferError),
}

/// The boot phase has already prepared the only scanout owner before AP startup.
/// This consumes it once; a failed preparation never publishes another address.
pub(crate) fn init_from_boot_info() -> Result<(), FramebufferInitError> {
    let (layout, mapping) = crate::resource_registry::mmio::take_boot_scanout()
        .map_err(FramebufferInitError::Resource)?;
    let mut framebuffer = Framebuffer::new(layout, PixelBuffer::Scanout(mapping))
        .map_err(FramebufferInitError::Framebuffer)?;
    framebuffer.clear(Color::BLACK);
    *FRAMEBUFFER.lock().unwrap_or_else(|e| e.into_inner()) = Some(framebuffer);
    Ok(())
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
    if FRAMEBUFFER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_some()
    {
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
///
/// # Safety
/// The caller must be a terminal panic path: the interrupted guard owner and
/// every ordinary framebuffer user must be unable to resume.
pub unsafe fn force_unlock_framebuffer() {
    // SAFETY: this boundary is called only by the terminal panic path. The
    // interrupted framebuffer guard and its execution never resume afterward.
    unsafe { FRAMEBUFFER.abandon_guard_for_terminal_panic() };
}
