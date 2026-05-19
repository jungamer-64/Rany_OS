#![no_std]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::len_without_is_empty)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::{self, Write};
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};
use exorust_sync::IrqPoisonLock;

use hal::port_io::{IoPort, PortU8};
use kernel_api::driver::{DeviceId, Driver, DriverType, DriverVersion};
use kernel_api::error::KapiResult;

mod driver_impl;
pub use driver_impl::*;

#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum ComPort {
    Com1 = 0x3F8,
    Com2 = 0x2F8,
    Com3 = 0x3E8,
    Com4 = 0x2E8,
}

mod reg {
    pub const DATA: u16 = 0;
    pub const IER: u16 = 1;
    pub const FCR: u16 = 2;
    pub const LCR: u16 = 3;
    pub const MCR: u16 = 4;
    pub const LSR: u16 = 5;
    pub const SCRATCH: u16 = 7;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DataBits {
    Bits5 = 0b00,
    Bits6 = 0b01,
    Bits7 = 0b10,
    Bits8 = 0b11,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StopBits {
    Stop1 = 0b0 << 2,
    Stop2 = 0b1 << 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Parity {
    None = 0b000 << 3,
    Odd = 0b001 << 3,
    Even = 0b011 << 3,
    Mark = 0b101 << 3,
    Space = 0b111 << 3,
}

#[derive(Debug, Clone, Copy)]
pub struct LineStatus(u8);

impl LineStatus {
    pub const DATA_READY: u8 = 1 << 0;
    pub const OVERRUN_ERROR: u8 = 1 << 1;
    pub const PARITY_ERROR: u8 = 1 << 2;
    pub const FRAMING_ERROR: u8 = 1 << 3;
    pub const BREAK_INTERRUPT: u8 = 1 << 4;
    pub const TX_HOLDING_EMPTY: u8 = 1 << 5;
    pub const TX_EMPTY: u8 = 1 << 6;
    pub const FIFO_ERROR: u8 = 1 << 7;
    pub fn from_u8(val: u8) -> Self {
        Self(val)
    }
    pub fn is_data_ready(&self) -> bool {
        self.0 & Self::DATA_READY != 0
    }
    pub fn is_tx_ready(&self) -> bool {
        self.0 & Self::TX_HOLDING_EMPTY != 0
    }
}

pub struct InterruptEnable;
impl InterruptEnable {
    pub const RX_AVAILABLE: u8 = 1 << 0;
    pub const TX_EMPTY: u8 = 1 << 1;
    pub const LINE_STATUS: u8 = 1 << 2;
    pub const MODEM_STATUS: u8 = 1 << 3;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaudRate {
    Baud115200 = 1,
    Baud57600 = 2,
    Baud38400 = 3,
    Baud19200 = 6,
    Baud9600 = 12,
    Baud4800 = 24,
    Baud2400 = 48,
    Baud1200 = 96,
}

pub struct SerialPort {
    base: u16,
    initialized: AtomicBool,
}

impl SerialPort {
    pub const fn new(port: ComPort) -> Self {
        Self {
            base: port as u16,
            initialized: AtomicBool::new(false),
        }
    }
    fn port_at<T>(&self, offset: u16) -> IoPort<T>
    where
        T: Copy + x86_64::instructions::port::PortRead + x86_64::instructions::port::PortWrite,
    {
        IoPort::new(self.base + offset)
    }
    pub fn init(
        &self,
        baud_rate: BaudRate,
        data_bits: DataBits,
        stop_bits: StopBits,
        parity: Parity,
    ) -> Result<(), SerialError> {
        let mut data_port: PortU8 = self.port_at(reg::DATA);
        let mut ier_port: PortU8 = self.port_at(reg::IER);
        let mut fcr_port: PortU8 = self.port_at(reg::FCR);
        let mut lcr_port: PortU8 = self.port_at(reg::LCR);
        let mut mcr_port: PortU8 = self.port_at(reg::MCR);
        let mut sr_port: PortU8 = self.port_at(reg::SCRATCH);
        ier_port.write(0x00);
        lcr_port.write(1 << 7);
        let divisor = baud_rate as u16;
        data_port.write((divisor & 0xFF) as u8);
        ier_port.write(((divisor >> 8) & 0xFF) as u8);
        lcr_port.write((data_bits as u8) | (stop_bits as u8) | (parity as u8));
        fcr_port.write(0x01 | 0x02 | 0x04 | 0xC0);
        mcr_port.write(0x01 | 0x02 | 0x08);
        mcr_port.write(0x10 | 0x01 | 0x02 | 0x08);
        data_port.write(0xAE);
        if data_port.read() != 0xAE {
            return Err(SerialError::InitFailed);
        }
        mcr_port.write(0x01 | 0x02 | 0x08);
        sr_port.write(0x55);
        if sr_port.read() != 0x55 {
            return Err(SerialError::InitFailed);
        }
        self.initialized.store(true, Ordering::SeqCst);
        Ok(())
    }
    pub fn line_status(&self) -> LineStatus {
        LineStatus::from_u8(self.port_at(reg::LSR).read())
    }
    pub fn can_transmit(&self) -> bool {
        self.line_status().is_tx_ready()
    }
    pub fn can_receive(&self) -> bool {
        self.line_status().is_data_ready()
    }
    pub fn send(&self, byte: u8) {
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while !self.can_transmit() {
            core::hint::spin_loop();
        }
        self.port_at(reg::DATA).write(byte);
    }
    pub fn send_str(&self, s: &str) {
        for byte in s.bytes() {
            self.send(byte);
        }
    }
    pub fn try_receive(&self) -> Result<u8, SerialError> {
        if self.can_receive() {
            Ok(self.port_at(reg::DATA).read())
        } else {
            Err(SerialError::NoData)
        }
    }
    pub fn set_interrupts(&self, rx: bool, tx: bool) {
        let mut flags = 0u8;
        if rx {
            flags |= InterruptEnable::RX_AVAILABLE;
        }
        if tx {
            flags |= InterruptEnable::TX_EMPTY;
        }
        self.port_at(reg::IER).write(flags);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialError {
    InitFailed,
    BufferFull,
    NoData,
    FramingError,
    ParityError,
    OverrunError,
}

const RX_BUFFER_SIZE: usize = 256;
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
}

pub struct AsyncSerialPort {
    port: SerialPort,
    rx_buffer: RxBuffer,
    waker: IrqPoisonLock<Option<Waker>>,
}

impl AsyncSerialPort {
    pub const fn new(port: ComPort) -> Self {
        Self {
            port: SerialPort::new(port),
            rx_buffer: RxBuffer::new(),
            waker: IrqPoisonLock::new(None),
        }
    }
    pub fn init(&self, baud_rate: BaudRate) -> Result<(), SerialError> {
        self.port
            .init(baud_rate, DataBits::Bits8, StopBits::Stop1, Parity::None)
    }
    pub fn handle_interrupt(&self) {
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while let Ok(byte) = self.port.try_receive() {
            self.rx_buffer.push(byte);
        }
        if let Some(waker) = self.waker.lock().unwrap_or_else(|e| e.into_inner()).take() {
            waker.wake();
        }
    }
    pub fn send_str(&self, s: &str) {
        self.port.send_str(s);
    }
    pub fn read_byte(&self) -> SerialReadFuture<'_> {
        SerialReadFuture { port: self }
    }
}

pub struct SerialReadFuture<'a> {
    port: &'a AsyncSerialPort,
}
impl<'a> Future for SerialReadFuture<'a> {
    type Output = u8;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(byte) = self.port.rx_buffer.pop() {
            return Poll::Ready(byte);
        }
        if let Ok(byte) = self.port.port.try_receive() {
            return Poll::Ready(byte);
        }
        *self.port.waker.lock().unwrap_or_else(|e| e.into_inner()) = Some(cx.waker().clone());
        if let Some(byte) = self.port.rx_buffer.pop() {
            return Poll::Ready(byte);
        }
        if !x86_64::instructions::interrupts::are_enabled() {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputEvent {
    Line(String),
    ArrowUp,
    ArrowDown,
    ArrowLeft,
    ArrowRight,
    Home,
    End,
    Tab,
    Interrupt,
    Eof,
    Delete,
}

pub struct LineEditor {
    buffer: Vec<u8>,
    cursor_pos: usize,
}
impl LineEditor {
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(256),
            cursor_pos: 0,
        }
    }
    pub fn content(&self) -> String {
        String::from_utf8_lossy(&self.buffer).into_owned()
    }
    pub fn set_content(&mut self, s: &str) {
        self.buffer.clear();
        self.buffer.extend_from_slice(s.as_bytes());
        self.cursor_pos = self.buffer.len();
    }
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.cursor_pos = 0;
    }
    pub fn len(&self) -> usize {
        self.buffer.len()
    }
    pub fn insert(&mut self, c: u8) -> bool {
        if self.buffer.len() >= 255 {
            return false;
        }
        if self.cursor_pos == self.buffer.len() {
            self.buffer.push(c);
        } else {
            self.buffer.insert(self.cursor_pos, c);
        }
        self.cursor_pos += 1;
        true
    }
    pub fn backspace(&mut self) -> bool {
        if self.cursor_pos > 0 {
            self.cursor_pos -= 1;
            self.buffer.remove(self.cursor_pos);
            true
        } else {
            false
        }
    }
    pub fn delete(&mut self) -> bool {
        if self.cursor_pos < self.buffer.len() {
            self.buffer.remove(self.cursor_pos);
            true
        } else {
            false
        }
    }
    pub fn move_left(&mut self) -> bool {
        if self.cursor_pos > 0 {
            self.cursor_pos -= 1;
            true
        } else {
            false
        }
    }
    pub fn move_right(&mut self) -> bool {
        if self.cursor_pos < self.buffer.len() {
            self.cursor_pos += 1;
            true
        } else {
            false
        }
    }
    pub fn move_home(&mut self) {
        self.cursor_pos = 0;
    }
    pub fn move_end(&mut self) {
        self.cursor_pos = self.buffer.len();
    }
    pub fn cursor(&self) -> usize {
        self.cursor_pos
    }
}

pub async fn read_line_advanced(editor: &mut LineEditor) -> InputEvent {
    let port = &SERIAL1;
    // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
    loop {
        let byte = port.read_byte().await;
        match byte {
            b'\r' | b'\n' => {
                port.port.send(b'\r');
                port.port.send(b'\n');
                let line = editor.content();
                editor.clear();
                return InputEvent::Line(line);
            }
            0x08 | 0x7F => {
                if editor.backspace() {
                    port.port.send(0x08);
                    port.port.send(b' ');
                    port.port.send(0x08);
                }
            }
            b'\t' => {
                return InputEvent::Tab;
            }
            0x03 => {
                port.port.send(b'^');
                port.port.send(b'C');
                port.port.send(b'\r');
                port.port.send(b'\n');
                editor.clear();
                return InputEvent::Interrupt;
            }
            0x04 => {
                if editor.len() == 0 {
                    return InputEvent::Eof;
                }
            }
            0x1B => {
                let next = port.read_byte().await;
                if next == b'[' {
                    let code = port.read_byte().await;
                    match code {
                        b'A' => return InputEvent::ArrowUp,
                        b'B' => return InputEvent::ArrowDown,
                        b'C' => {
                            if editor.move_right() {
                                port.port.send(0x1B);
                                port.port.send(b'[');
                                port.port.send(b'C');
                            }
                        }
                        b'D' => {
                            if editor.move_left() {
                                port.port.send(0x1B);
                                port.port.send(b'[');
                                port.port.send(b'D');
                            }
                        }
                        b'H' => {
                            let moves = editor.cursor();
                            editor.move_home();
                            for _ in 0..moves {
                                port.port.send(0x1B);
                                port.port.send(b'[');
                                port.port.send(b'D');
                            }
                        }
                        b'F' => {
                            let moves = editor.len() - editor.cursor();
                            editor.move_end();
                            for _ in 0..moves {
                                port.port.send(0x1B);
                                port.port.send(b'[');
                                port.port.send(b'C');
                            }
                        }
                        b'3' => {
                            let tilde = port.read_byte().await;
                            if tilde == b'~' && editor.delete() {
                                redraw_from_cursor(port, editor);
                            }
                        }
                        _ => {}
                    }
                }
            }
            0x20..=0x7E => {
                if editor.insert(byte) {
                    if editor.cursor() == editor.len() {
                        port.port.send(byte);
                    } else {
                        redraw_from_cursor(port, editor);
                    }
                }
            }
            _ => {}
        }
    }
}
