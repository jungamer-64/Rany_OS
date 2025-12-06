// ============================================================================
// src/io/audio/hda/global.rs - Global Driver Instance and Public API
// ============================================================================
//!
//! HDA ドライバのグローバルインスタンスと公開API。
//!
//! - グローバルドライバインスタンス
//! - 割り込みハンドラ
//! - 初期化関数
//! - 公開ユーティリティ関数

#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use spin::Mutex;

use crate::io::pci::{find_by_class, Bar};
use crate::task::interrupt_waker;

use super::controller::HdaController;
use super::regs::*;
use super::types::{HdaError, HdaResult};

// ============================================================================
// Interrupt Support
// ============================================================================

/// HDA 割り込みベクタ番号
/// PCI デバイスの interrupt_line から動的に決定される
static HDA_IRQ: AtomicU8 = AtomicU8::new(0);

/// HDA 割り込み発生カウンタ（デバッグ用）
static HDA_INTERRUPT_COUNT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// HDA 割り込みペンディングフラグ
static HDA_INTERRUPT_PENDING: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Global HDA Driver Instance
// ============================================================================

static HDA_DRIVER: Mutex<Option<HdaController>> = Mutex::new(None);

/// Initialize the HDA driver
pub fn init() -> HdaResult<()> {
    crate::log!("[HDA] Searching for Intel HD Audio device...\n");

    // Search for HDA device (class 04, subclass 03)
    let devices = find_by_class(HDA_CLASS, HDA_SUBCLASS);

    if devices.is_empty() {
        crate::log!("[HDA] No HD Audio device found\n");
        return Err(HdaError::NoDevice);
    }

    let pci_device = devices.into_iter().next().unwrap();

    crate::log!(
        "[HDA] Found device: {:04x}:{:04x} at {:02x}:{:02x}.{}\n",
        pci_device.vendor_id.0,
        pci_device.device_id.0,
        pci_device.bdf.bus(),
        pci_device.bdf.device(),
        pci_device.bdf.function()
    );

    // PCI 割り込みライン（IRQ）を保存
    let irq = pci_device.interrupt_line;
    if irq > 0 && irq < 16 {
        HDA_IRQ.store(irq, Ordering::SeqCst);
        crate::log!("[HDA] IRQ: {} (interrupt_pin: {})\n", irq, pci_device.interrupt_pin);
    } else {
        crate::log!("[HDA] Warning: Invalid IRQ {} (will use polling mode)\n", irq);
    }

    // Get BAR0 (MMIO)
    let mmio_base = match &pci_device.bars[0] {
        Some(Bar::Memory32 { base, .. }) => *base as u64,
        Some(Bar::Memory64 { base, .. }) => *base,
        _ => return Err(HdaError::InvalidBar),
    };

    crate::log!("[HDA] MMIO base: 0x{:016x}\n", mmio_base);

    // Create and initialize controller
    let mut controller = HdaController::new(pci_device, mmio_base);
    controller.init()?;

    *HDA_DRIVER.lock() = Some(controller);

    Ok(())
}

/// Access the HDA driver
pub fn with_driver<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&HdaController) -> R,
{
    HDA_DRIVER.lock().as_ref().map(f)
}

/// Access the HDA driver mutably
pub fn with_driver_mut<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut HdaController) -> R,
{
    HDA_DRIVER.lock().as_mut().map(f)
}

/// Play a beep using the codec's beep generator
pub fn beep(frequency_hz: u32, duration_ms: u32) -> HdaResult<()> {
    let driver = HDA_DRIVER.lock();
    let driver = driver.as_ref().ok_or(HdaError::NoDevice)?;

    if driver.codecs.is_empty() {
        return Err(HdaError::NoCodec);
    }

    driver.beep_duration(driver.codecs[0].address, frequency_hz, duration_ms)
}

/// Play a square wave tone
pub fn play_tone(frequency_hz: u32, duration_ms: u32) -> HdaResult<()> {
    let mut driver = HDA_DRIVER.lock();
    let driver = driver.as_mut().ok_or(HdaError::NoDevice)?;

    driver.play_square_wave(frequency_hz, duration_ms)
}

/// Quick test: play a startup beep sequence
pub fn test_beep() -> HdaResult<()> {
    crate::log!("[HDA] Playing test beep sequence...\n");

    // Try beep generator first
    if beep(440, 200).is_ok() {
        HdaController::delay_us(100000);
        beep(880, 200)?;
        HdaController::delay_us(100000);
        beep(440, 400)?;
        return Ok(());
    }

    // Fall back to square wave if no beep generator
    play_tone(440, 200)?;
    HdaController::delay_us(100000);
    play_tone(880, 200)?;
    HdaController::delay_us(100000);
    play_tone(440, 400)?;

    Ok(())
}

// ============================================================================
// HDA Interrupt Handler
// ============================================================================

/// HDA 割り込みハンドラ
///
/// この関数は IDT から呼び出される。
/// 割り込みステータスをクリアし、必要に応じて待機中のタスクを起床させる。
pub fn handle_interrupt() {
    let count = HDA_INTERRUPT_COUNT.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    
    // コントローラーの割り込みステータスを読み取り・クリア
    if let Some(driver) = HDA_DRIVER.lock().as_ref() {
        // INTSTS レジスタを読み取り
        let intsts = driver.read32(REG_INTSTS);
        
        if intsts != 0 {
            // ストリーム完了割り込みの処理
            if intsts & INTSTS_SIS_MASK != 0 {
                // 各ストリームの割り込みを確認
                for stream in 0..8u32 {
                    if intsts & (1 << stream) != 0 {
                        // ストリームステータスレジスタをクリア
                        // (ストリーム N のステータスは offset 0x80 + N*0x20 + 0x03)
                        let stream_offset = 0x80 + stream * 0x20;
                        let sts = driver.read8(stream_offset + 0x03);
                        driver.write8(stream_offset + 0x03, sts); // Write-1-to-clear
                    }
                }
            }
            
            // Controller Interrupt Status をクリア (Write-1-to-clear)
            driver.write32(REG_INTSTS, intsts);
            
            // ペンディングフラグを設定
            HDA_INTERRUPT_PENDING.store(true, Ordering::SeqCst);
        }
    }

    // Interrupt-Waker ブリッジに通知（オーディオ待機中のタスクを起床）
    // HDA の IRQ 番号を使用して汎用 Irq ソースとして通知
    let irq = HDA_IRQ.load(Ordering::SeqCst);
    interrupt_waker::wake_from_interrupt(interrupt_waker::InterruptSource::Irq(irq));

    // デバッグ出力（最初の数回のみ）
    if count < 5 {
        crate::log!("[HDA] Interrupt #{}\n", count);
    }
}

/// HDA で使用する IRQ 番号を取得
pub fn get_irq() -> u8 {
    HDA_IRQ.load(Ordering::SeqCst)
}

/// 割り込みペンディングフラグをクリアして状態を返す
pub fn clear_interrupt_pending() -> bool {
    HDA_INTERRUPT_PENDING.swap(false, Ordering::SeqCst)
}

/// 割り込み発生回数を取得
pub fn get_interrupt_count() -> u64 {
    HDA_INTERRUPT_COUNT.load(Ordering::SeqCst)
}

/// HDA 割り込みをアンマスク（有効化）
pub fn enable_irq() {
    let irq = HDA_IRQ.load(Ordering::SeqCst);
    if irq > 0 && irq < 16 {
        crate::interrupts::unmask_irq(irq);
        crate::log!("[HDA] IRQ {} unmasked\n", irq);
    }
}

/// HDA 割り込みをマスク（無効化）
pub fn disable_irq() {
    let irq = HDA_IRQ.load(Ordering::SeqCst);
    if irq > 0 && irq < 16 {
        crate::interrupts::mask_irq(irq);
        crate::log!("[HDA] IRQ {} masked\n", irq);
    }
}
