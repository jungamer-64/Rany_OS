// ============================================================================
// src/io/serial.rs - Serial Port Driver (UART 16550)
// デバッグ出力およびコンソール入出力用
// ============================================================================
//!
//! # シリアルポートドライバ
//!
//! UART 16550互換のシリアルポートドライバ。
//! QEMUなどのエミュレータでのデバッグ出力に使用。
//!
//! ## 機能
//! - 非同期送受信
//! - 複数のボーレート対応
//! - FIFOバッファ
//! - 割り込みまたはポーリングモード

#![allow(dead_code)]

use core::fmt::{self, Write};
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};
use spin::Mutex;
use x86_64::instructions::port::Port;

// ============================================================================
// シリアルポート定数
// ============================================================================

/// COM1ベースポート
pub const COM1: u16 = 0x3F8;
/// COM2ベースポート
pub const COM2: u16 = 0x2F8;
/// COM3ベースポート
pub const COM3: u16 = 0x3E8;
/// COM4ベースポート
pub const COM4: u16 = 0x2E8;

// レジスタオフセット
mod reg {
    pub const DATA: u16 = 0; // データレジスタ（DLAB=0）
    pub const DLL: u16 = 0; // 分周器下位（DLAB=1）
    pub const DLH: u16 = 1; // 分周器上位（DLAB=1）
    pub const IER: u16 = 1; // 割り込み有効化レジスタ（DLAB=0）
    pub const IIR: u16 = 2; // 割り込み識別レジスタ（読み取り）
    pub const FCR: u16 = 2; // FIFOコントロールレジスタ（書き込み）
    pub const LCR: u16 = 3; // ラインコントロールレジスタ
    pub const MCR: u16 = 4; // モデムコントロールレジスタ
    pub const LSR: u16 = 5; // ラインステータスレジスタ
    pub const MSR: u16 = 6; // モデムステータスレジスタ
    pub const SR: u16 = 7; // スクラッチレジスタ
}

// ラインステータスビット
mod lsr {
    pub const DATA_READY: u8 = 1 << 0;
    pub const OVERRUN_ERROR: u8 = 1 << 1;
    pub const PARITY_ERROR: u8 = 1 << 2;
    pub const FRAMING_ERROR: u8 = 1 << 3;
    pub const BREAK_INTERRUPT: u8 = 1 << 4;
    pub const TX_HOLDING_EMPTY: u8 = 1 << 5;
    pub const TX_EMPTY: u8 = 1 << 6;
    pub const FIFO_ERROR: u8 = 1 << 7;
}

// ラインコントロール設定
mod lcr {
    pub const DATA_5: u8 = 0b00;
    pub const DATA_6: u8 = 0b01;
    pub const DATA_7: u8 = 0b10;
    pub const DATA_8: u8 = 0b11;
    pub const STOP_1: u8 = 0 << 2;
    pub const STOP_2: u8 = 1 << 2;
    pub const PARITY_NONE: u8 = 0 << 3;
    pub const PARITY_ODD: u8 = 1 << 3;
    pub const PARITY_EVEN: u8 = 3 << 3;
    pub const PARITY_MARK: u8 = 5 << 3;
    pub const PARITY_SPACE: u8 = 7 << 3;
    pub const DLAB: u8 = 1 << 7;
}

// 割り込み有効化ビット
mod ier {
    pub const RX_AVAILABLE: u8 = 1 << 0;
    pub const TX_EMPTY: u8 = 1 << 1;
    pub const LINE_STATUS: u8 = 1 << 2;
    pub const MODEM_STATUS: u8 = 1 << 3;
}

// FIFOコントロール設定
mod fcr {
    pub const ENABLE: u8 = 1 << 0;
    pub const RX_CLEAR: u8 = 1 << 1;
    pub const TX_CLEAR: u8 = 1 << 2;
    pub const DMA_MODE: u8 = 1 << 3;
    pub const TRIGGER_1: u8 = 0b00 << 6;
    pub const TRIGGER_4: u8 = 0b01 << 6;
    pub const TRIGGER_8: u8 = 0b10 << 6;
    pub const TRIGGER_14: u8 = 0b11 << 6;
}

// モデムコントロール設定
mod mcr {
    pub const DTR: u8 = 1 << 0;
    pub const RTS: u8 = 1 << 1;
    pub const OUT1: u8 = 1 << 2;
    pub const OUT2: u8 = 1 << 3; // 割り込み有効化
    pub const LOOPBACK: u8 = 1 << 4;
}

/// ボーレート
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaudRate {
    Baud115200,
    Baud57600,
    Baud38400,
    Baud19200,
    Baud9600,
    Baud4800,
    Baud2400,
    Baud1200,
}

impl BaudRate {
    /// 分周器値を取得（115200基準）
    fn divisor(&self) -> u16 {
        match self {
            BaudRate::Baud115200 => 1,
            BaudRate::Baud57600 => 2,
            BaudRate::Baud38400 => 3,
            BaudRate::Baud19200 => 6,
            BaudRate::Baud9600 => 12,
            BaudRate::Baud4800 => 24,
            BaudRate::Baud2400 => 48,
            BaudRate::Baud1200 => 96,
        }
    }
}

// ============================================================================
// シリアルポートドライバ
// ============================================================================

/// シリアルポートドライバ
pub struct SerialPort {
    base: u16,
    initialized: AtomicBool,
}

impl SerialPort {
    /// 新しいシリアルポートを作成
    pub const fn new(base: u16) -> Self {
        Self {
            base,
            initialized: AtomicBool::new(false),
        }
    }

    /// シリアルポートを初期化
    pub fn init(&self, baud_rate: BaudRate) -> Result<(), SerialError> {
        unsafe {
            let mut data_port: Port<u8> = Port::new(self.base + reg::DATA);
            let mut ier_port: Port<u8> = Port::new(self.base + reg::IER);
            let mut fcr_port: Port<u8> = Port::new(self.base + reg::FCR);
            let mut lcr_port: Port<u8> = Port::new(self.base + reg::LCR);
            let mut mcr_port: Port<u8> = Port::new(self.base + reg::MCR);
            let mut sr_port: Port<u8> = Port::new(self.base + reg::SR);

            // 割り込みを無効化
            ier_port.write(0x00);

            // ボーレート設定（DLAB=1）
            lcr_port.write(lcr::DLAB);

            let divisor = baud_rate.divisor();
            data_port.write((divisor & 0xFF) as u8); // DLL
            ier_port.write(((divisor >> 8) & 0xFF) as u8); // DLH

            // 8N1設定（8データビット、パリティなし、1ストップビット）
            lcr_port.write(lcr::DATA_8 | lcr::STOP_1 | lcr::PARITY_NONE);

            // FIFOを有効化、14バイトトリガ
            fcr_port.write(fcr::ENABLE | fcr::RX_CLEAR | fcr::TX_CLEAR | fcr::TRIGGER_14);

            // DTR、RTS、OUT2（割り込み）を有効化
            mcr_port.write(mcr::DTR | mcr::RTS | mcr::OUT2);

            // ループバックモードでテスト
            mcr_port.write(mcr::LOOPBACK | mcr::DTR | mcr::RTS | mcr::OUT2);

            // テストバイトを送信
            data_port.write(0xAE);

            // 読み戻しチェック
            let response = data_port.read();
            if response != 0xAE {
                return Err(SerialError::InitFailed);
            }

            // 通常モードに戻す
            mcr_port.write(mcr::DTR | mcr::RTS | mcr::OUT2);

            // スクラッチレジスタでさらにテスト
            sr_port.write(0x55);
            if sr_port.read() != 0x55 {
                return Err(SerialError::InitFailed);
            }

            self.initialized.store(true, Ordering::SeqCst);
        }

        Ok(())
    }

    /// 受信データがあるか確認
    pub fn can_receive(&self) -> bool {
        unsafe {
            let mut lsr_port: Port<u8> = Port::new(self.base + reg::LSR);
            (lsr_port.read() & lsr::DATA_READY) != 0
        }
    }

    /// 送信可能か確認
    pub fn can_transmit(&self) -> bool {
        unsafe {
            let mut lsr_port: Port<u8> = Port::new(self.base + reg::LSR);
            (lsr_port.read() & lsr::TX_HOLDING_EMPTY) != 0
        }
    }

    /// バイトを送信（ブロッキング）
    pub fn send(&self, byte: u8) {
        while !self.can_transmit() {
            core::hint::spin_loop();
        }

        unsafe {
            let mut data_port: Port<u8> = Port::new(self.base + reg::DATA);
            data_port.write(byte);
        }
    }

    /// バイトを受信（ブロッキング）
    pub fn receive(&self) -> u8 {
        while !self.can_receive() {
            core::hint::spin_loop();
        }

        unsafe {
            let mut data_port: Port<u8> = Port::new(self.base + reg::DATA);
            data_port.read()
        }
    }

    /// バイトを送信（ノンブロッキング）
    pub fn try_send(&self, byte: u8) -> Result<(), SerialError> {
        if self.can_transmit() {
            unsafe {
                let mut data_port: Port<u8> = Port::new(self.base + reg::DATA);
                data_port.write(byte);
            }
            Ok(())
        } else {
            Err(SerialError::BufferFull)
        }
    }

    /// バイトを受信（ノンブロッキング）
    pub fn try_receive(&self) -> Result<u8, SerialError> {
        if self.can_receive() {
            unsafe {
                let mut data_port: Port<u8> = Port::new(self.base + reg::DATA);
                Ok(data_port.read())
            }
        } else {
            Err(SerialError::NoData)
        }
    }

    /// 文字列を送信
    pub fn send_str(&self, s: &str) {
        for byte in s.bytes() {
            self.send(byte);
        }
    }

    /// 割り込みを有効化
    pub fn enable_interrupts(&self, rx: bool, tx: bool) {
        let mut flags = 0u8;
        if rx {
            flags |= ier::RX_AVAILABLE;
        }
        if tx {
            flags |= ier::TX_EMPTY;
        }

        unsafe {
            let mut ier_port: Port<u8> = Port::new(self.base + reg::IER);
            ier_port.write(flags);
        }
    }

    /// 割り込みを無効化
    pub fn disable_interrupts(&self) {
        unsafe {
            let mut ier_port: Port<u8> = Port::new(self.base + reg::IER);
            ier_port.write(0);
        }
    }

    /// ラインステータスを取得
    pub fn line_status(&self) -> u8 {
        unsafe {
            let mut lsr_port: Port<u8> = Port::new(self.base + reg::LSR);
            lsr_port.read()
        }
    }
}

impl Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.send_str(s);
        Ok(())
    }
}

// ============================================================================
// エラー型
// ============================================================================

/// シリアルポートエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialError {
    /// 初期化失敗
    InitFailed,
    /// 送信バッファが満杯
    BufferFull,
    /// 受信データなし
    NoData,
    /// フレーミングエラー
    FramingError,
    /// パリティエラー
    ParityError,
    /// オーバーランエラー
    OverrunError,
}

// ============================================================================
// 非同期シリアルポート
// ============================================================================

const RX_BUFFER_SIZE: usize = 256;

/// 受信バッファ
struct RxBuffer {
    buffer: [AtomicU8; RX_BUFFER_SIZE],
    head: AtomicUsize,
    tail: AtomicUsize,
}

impl RxBuffer {
    const fn new() -> Self {
        const ZERO: AtomicU8 = AtomicU8::new(0);
        Self {
            buffer: [ZERO; RX_BUFFER_SIZE],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    fn push(&self, byte: u8) -> bool {
        let tail = self.tail.load(Ordering::Relaxed);
        let next_tail = (tail + 1) % RX_BUFFER_SIZE;

        if next_tail == self.head.load(Ordering::Acquire) {
            return false;
        }

        self.buffer[tail].store(byte, Ordering::Relaxed);
        self.tail.store(next_tail, Ordering::Release);
        true
    }

    fn pop(&self) -> Option<u8> {
        let head = self.head.load(Ordering::Relaxed);
        if head == self.tail.load(Ordering::Acquire) {
            return None;
        }

        let byte = self.buffer[head].load(Ordering::Relaxed);
        self.head
            .store((head + 1) % RX_BUFFER_SIZE, Ordering::Release);
        Some(byte)
    }

    fn is_empty(&self) -> bool {
        self.head.load(Ordering::Acquire) == self.tail.load(Ordering::Acquire)
    }
}

/// 非同期シリアルポート
pub struct AsyncSerialPort {
    port: SerialPort,
    rx_buffer: RxBuffer,
    waker: Mutex<Option<Waker>>,
}

impl AsyncSerialPort {
    /// 新しい非同期シリアルポートを作成
    pub const fn new(base: u16) -> Self {
        Self {
            port: SerialPort::new(base),
            rx_buffer: RxBuffer::new(),
            waker: Mutex::new(None),
        }
    }

    /// 初期化
    pub fn init(&self, baud_rate: BaudRate) -> Result<(), SerialError> {
        self.port.init(baud_rate)
    }

    /// 割り込みハンドラ（ISRから呼ばれる）
    pub fn handle_interrupt(&self) {
        // 受信データを読み取ってバッファに追加
        while self.port.can_receive() {
            if let Ok(byte) = self.port.try_receive() {
                self.rx_buffer.push(byte);
            }
        }

        // 待機中のタスクを起床
        if let Some(waker) = self.waker.lock().take() {
            waker.wake();
        }
    }

    /// バイトを送信
    pub fn send(&self, byte: u8) {
        self.port.send(byte);
    }

    /// 文字列を送信
    pub fn send_str(&self, s: &str) {
        self.port.send_str(s);
    }

    /// バイトを非同期で受信
    pub fn read_byte(&self) -> SerialReadFuture<'_> {
        SerialReadFuture { port: self }
    }

    /// バイトをポーリングで受信
    pub fn poll_byte(&self) -> Option<u8> {
        self.rx_buffer
            .pop()
            .or_else(|| self.port.try_receive().ok())
    }
}

/// シリアル受信Future
pub struct SerialReadFuture<'a> {
    port: &'a AsyncSerialPort,
}

impl<'a> Future for SerialReadFuture<'a> {
    type Output = u8;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // まずバッファをチェック
        if let Some(byte) = self.port.rx_buffer.pop() {
            return Poll::Ready(byte);
        }

        // 直接ポートをチェック
        if let Ok(byte) = self.port.port.try_receive() {
            return Poll::Ready(byte);
        }

        // Wakerを登録
        *self.port.waker.lock() = Some(cx.waker().clone());

        // 再度チェック
        if let Some(byte) = self.port.rx_buffer.pop() {
            return Poll::Ready(byte);
        }

        if let Ok(byte) = self.port.port.try_receive() {
            return Poll::Ready(byte);
        }

        Poll::Pending
    }
}

// ============================================================================
// グローバルシリアルポート
// ============================================================================

/// グローバルCOM1シリアルポート
static SERIAL1: AsyncSerialPort = AsyncSerialPort::new(COM1);

/// COM1を初期化
pub fn init() -> Result<(), SerialError> {
    SERIAL1.init(BaudRate::Baud115200)?;
    SERIAL1.port.enable_interrupts(true, false);
    crate::log!("[SERIAL] COM1 initialized at 115200 baud\n");
    Ok(())
}

/// COM1にアクセス
pub fn serial1() -> &'static AsyncSerialPort {
    &SERIAL1
}

/// シリアル割り込みハンドラ
pub fn handle_interrupt() {
    SERIAL1.handle_interrupt();
}

// ============================================================================
// マクロ
// ============================================================================

/// シリアルポートに出力
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::io::serial::_print(format_args!($($arg)*))
    };
}

/// シリアルポートに出力（改行付き）
#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($($arg:tt)*) => ($crate::serial_print!("{}\n", format_args!($($arg)*)));
}

/// 内部出力関数
#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use core::fmt::Write;

    // シリアルポートに書き込み
    unsafe {
        let _ = (&SERIAL1.port as *const SerialPort as *mut SerialPort)
            .as_mut()
            .map(|port| port.write_fmt(args));
    }
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_baud_rate_divisor() {
        assert_eq!(BaudRate::Baud115200.divisor(), 1);
        assert_eq!(BaudRate::Baud9600.divisor(), 12);
    }
}
