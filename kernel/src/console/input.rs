use crate::sync::PoisonLock;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use hid_driver::keyboard::KeyEventExt;

use crate::io::hid::keyboard::{self, KeyCode, KeyEvent, KeyState};

const TTY_RX_CAPACITY: usize = 4096;
const GUI_EVENT_CAPACITY: usize = 256;

static INPUT_HUB: PoisonLock<ConsoleInputHub> = PoisonLock::new(ConsoleInputHub::new());
static INPUT_TAP_INSTALLED: AtomicBool = AtomicBool::new(false);
static DROPPED_TTY_BYTES: AtomicU64 = AtomicU64::new(0);
static DROPPED_GUI_EVENTS: AtomicU64 = AtomicU64::new(0);

struct ConsoleInputHub {
    tty_buf: [u8; TTY_RX_CAPACITY],
    tty_head: usize,
    tty_len: usize,
    gui_buf: [Option<KeyEvent>; GUI_EVENT_CAPACITY],
    gui_head: usize,
    gui_len: usize,
}

impl ConsoleInputHub {
    const fn new() -> Self {
        Self {
            tty_buf: [0; TTY_RX_CAPACITY],
            tty_head: 0,
            tty_len: 0,
            gui_buf: [None; GUI_EVENT_CAPACITY],
            gui_head: 0,
            gui_len: 0,
        }
    }

    fn reset(&mut self) {
        self.tty_head = 0;
        self.tty_len = 0;
        self.gui_head = 0;
        self.gui_len = 0;
        let mut i = 0;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while i < self.gui_buf.len() {
            self.gui_buf[i] = None;
            i += 1;
        }
    }

    fn push_tty_byte(&mut self, byte: u8) -> bool {
        if self.tty_len >= self.tty_buf.len() {
            return false;
        }
        let tail = (self.tty_head + self.tty_len) % self.tty_buf.len();
        self.tty_buf[tail] = byte;
        self.tty_len += 1;
        true
    }

    fn pop_tty_bytes(&mut self, dst: &mut [u8]) -> usize {
        let mut read = 0;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while read < dst.len() && self.tty_len > 0 {
            dst[read] = self.tty_buf[self.tty_head];
            self.tty_head = (self.tty_head + 1) % self.tty_buf.len();
            self.tty_len -= 1;
            read += 1;
        }
        read
    }

    fn push_gui_event(&mut self, event: KeyEvent) -> bool {
        if self.gui_len >= self.gui_buf.len() {
            return false;
        }
        let tail = (self.gui_head + self.gui_len) % self.gui_buf.len();
        self.gui_buf[tail] = Some(event);
        self.gui_len += 1;
        true
    }

    fn pop_gui_event(&mut self) -> Option<KeyEvent> {
        if self.gui_len == 0 {
            return None;
        }
        let event = self.gui_buf[self.gui_head].take();
        self.gui_head = (self.gui_head + 1) % self.gui_buf.len();
        self.gui_len -= 1;
        event
    }
}

#[inline]
fn increment_dropped_gui_events() {
    let _ = DROPPED_GUI_EVENTS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        v.checked_add(1).or(Some(u64::MAX))
    });
}

#[inline]
fn increment_dropped_tty_bytes(by: u64) {
    if by == 0 {
        return;
    }
    let _ = DROPPED_TTY_BYTES.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        v.checked_add(by).or(Some(u64::MAX))
    });
}

pub fn install_keyboard_tap() {
    if INPUT_TAP_INSTALLED.swap(true, Ordering::AcqRel) {
        return;
    }
    keyboard::set_event_tap(Some(keyboard_event_tap));
}

fn keyboard_event_tap(event: KeyEvent) {
    handle_keyboard_tap_event(event);
}

fn handle_keyboard_tap_event(event: KeyEvent) {
    if let Some(vt_id) = vt_hotkey_target(event) {
        if event.state == KeyState::Pressed {
            let _ = crate::console::try_switch(vt_id);
        }
        return;
    }

    if let Ok(mut hub) = INPUT_HUB.try_lock() {
        if !hub.push_gui_event(event) {
            increment_dropped_gui_events();
        }
        if event.state == KeyState::Pressed {
            push_tty_from_key_event(&mut hub, event);
        }
        return;
    }

    increment_dropped_gui_events();
    if event.state == KeyState::Pressed {
        increment_dropped_tty_bytes(estimated_tty_bytes(event) as u64);
    }
}

fn vt_hotkey_target(event: KeyEvent) -> Option<u32> {
    if !event.modifiers.ctrl || !(event.modifiers.alt || event.modifiers.alt_gr) {
        return None;
    }

    let id = match event.key {
        KeyCode::F1 => 0,
        KeyCode::F2 => 1,
        KeyCode::F3 => 2,
        KeyCode::F4 => 3,
        KeyCode::F5 => 4,
        KeyCode::F6 => 5,
        KeyCode::F7 => 6,
        KeyCode::F8 => 7,
        _ => return None,
    };

    if id < super::MAX_VIRTUAL_CONSOLES as u32 {
        Some(id)
    } else {
        None
    }
}

fn push_tty_from_key_event(hub: &mut ConsoleInputHub, event: KeyEvent) {
    if let Some(seq) = ansi_sequence_for_key(event.key) {
        push_tty_bytes(hub, seq);
        return;
    }

    let ch = match event.key {
        KeyCode::Backspace => Some('\x08'),
        KeyCode::Enter | KeyCode::NumPadEnter => Some('\n'),
        KeyCode::Tab => Some('\t'),
        _ => event.to_char(),
    };

    if let Some(ch) = ch {
        let mut utf8 = [0u8; 4];
        let s = ch.encode_utf8(&mut utf8);
        push_tty_bytes(hub, s.as_bytes());
    }
}

fn push_tty_bytes(hub: &mut ConsoleInputHub, bytes: &[u8]) {
    for &b in bytes {
        if !hub.push_tty_byte(b) {
            increment_dropped_tty_bytes(1);
        }
    }
}

fn ansi_sequence_for_key(key: KeyCode) -> Option<&'static [u8]> {
    match key {
        KeyCode::Up => Some(b"\x1b[A"),
        KeyCode::Down => Some(b"\x1b[B"),
        KeyCode::Right => Some(b"\x1b[C"),
        KeyCode::Left => Some(b"\x1b[D"),
        KeyCode::Home => Some(b"\x1b[H"),
        KeyCode::End => Some(b"\x1b[F"),
        KeyCode::Insert => Some(b"\x1b[2~"),
        KeyCode::Delete => Some(b"\x1b[3~"),
        KeyCode::PageUp => Some(b"\x1b[5~"),
        KeyCode::PageDown => Some(b"\x1b[6~"),
        KeyCode::F1 => Some(b"\x1bOP"),
        KeyCode::F2 => Some(b"\x1bOQ"),
        KeyCode::F3 => Some(b"\x1bOR"),
        KeyCode::F4 => Some(b"\x1bOS"),
        _ => None,
    }
}

fn estimated_tty_bytes(event: KeyEvent) -> usize {
    if let Some(seq) = ansi_sequence_for_key(event.key) {
        return seq.len();
    }

    let ch = match event.key {
        KeyCode::Backspace => Some('\x08'),
        KeyCode::Enter | KeyCode::NumPadEnter => Some('\n'),
        KeyCode::Tab => Some('\t'),
        _ => event.to_char(),
    };

    ch.map(char::len_utf8).unwrap_or(0)
}

/// Non-blocking read for `/dev/console`.
pub fn read_tty_bytes(buf: &mut [u8]) -> usize {
    if buf.is_empty() {
        return 0;
    }
    let mut hub = INPUT_HUB.lock().unwrap_or_else(|e| e.into_inner());
    hub.pop_tty_bytes(buf)
}

/// Non-blocking pop for GUI polling path.
pub fn try_pop_key_event() -> Option<KeyEvent> {
    let mut hub = INPUT_HUB.try_lock().ok()?;
    hub.pop_gui_event()
}

pub fn dropped_input_counts() -> (u64, u64) {
    (
        DROPPED_TTY_BYTES.load(Ordering::Relaxed),
        DROPPED_GUI_EVENTS.load(Ordering::Relaxed),
    )
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub fn reset_input_hub_for_tests() {
    {
        let mut hub = INPUT_HUB.lock().unwrap_or_else(|e| e.into_inner());
        hub.reset();
    }
    DROPPED_TTY_BYTES.store(0, Ordering::Relaxed);
    DROPPED_GUI_EVENTS.store(0, Ordering::Relaxed);
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub fn inject_key_event_for_tests(event: KeyEvent) {
    handle_keyboard_tap_event(event);
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub fn inject_tty_bytes_for_tests(bytes: &[u8]) {
    let mut hub = INPUT_HUB.lock().unwrap_or_else(|e| e.into_inner());
    push_tty_bytes(&mut hub, bytes);
}
