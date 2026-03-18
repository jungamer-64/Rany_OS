use super::*;
use crate::drivers::hid::keyboard::{KeyCode, KeyEvent, KeyState, Modifiers};

fn key_event(key: KeyCode, state: KeyState, modifiers: Modifiers) -> KeyEvent {
    KeyEvent {
        key,
        state,
        modifiers,
        raw_scancode: 0,
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_ansi_color_rgb() {
    assert_eq!(AnsiColor::Black.to_rgb(), 0x000000);
    assert_eq!(AnsiColor::White.to_rgb(), 0xAAAAAA);
    assert_eq!(AnsiColor::BrightWhite.to_rgb(), 0xFFFFFF);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_terminal_buffer() {
    let mut buffer = TerminalBuffer::new(80, 25);
    buffer.write_str("Hello, World!");
    assert_eq!(buffer.cursor(), (13, 0));

    buffer.write_char('\n');
    assert_eq!(buffer.cursor(), (0, 1));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_ansi_parser() {
    let mut parser = AnsiParser::new();

    // 通常文字
    let action = parser.feed('A');
    assert!(matches!(action, Some(AnsiAction::Print('A'))));

    // エスケープシーケンス開始
    assert!(parser.feed('\x1b').is_none());
    assert!(parser.feed('[').is_none());

    // カーソル移動
    let action = parser.feed('H');
    assert!(matches!(
        action,
        Some(AnsiAction::SetCursor { row: 0, col: 0 })
    ));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_virtual_console() {
    let mut vc = VirtualConsole::new(0, 80, 25);
    vc.write("Hello\n");
    assert_eq!(vc.buffer().cursor(), (0, 1));

    // ANSIカラー
    vc.write("\x1b[31mRed\x1b[0m");
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_csi_cursor_default_param_moves_one() {
    let mut vc = VirtualConsole::new(0, 20, 5);
    vc.write("abc\nxyz");
    assert_eq!(vc.buffer().cursor(), (3, 1));

    // CUU with omitted parameter should behave as 1
    vc.write("\x1b[A");
    assert_eq!(vc.buffer().cursor(), (3, 0));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_private_mode_cursor_visibility() {
    let mut vc = VirtualConsole::new(0, 20, 5);
    vc.write("A\x1b[?25lB");

    assert_eq!(vc.buffer().get_cell(0, 0).map(|c| c.ch), Some('A'));
    assert_eq!(vc.buffer().get_cell(1, 0).map(|c| c.ch), Some('B'));
    assert!(!vc.buffer().cursor_visible());

    vc.write("\x1b[?25h");
    assert!(vc.buffer().cursor_visible());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_osc_st_terminator_is_not_rendered() {
    let mut vc = VirtualConsole::new(0, 40, 5);
    vc.write("X\x1b]0;title\x1b\\Y");

    assert_eq!(vc.buffer().get_cell(0, 0).map(|c| c.ch), Some('X'));
    assert_eq!(vc.buffer().get_cell(1, 0).map(|c| c.ch), Some('Y'));
    assert_eq!(vc.buffer().cursor(), (2, 0));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_console_input_hub_tty_and_gui_paths() {
    reset_input_hub_for_tests();

    inject_key_event_for_tests(key_event(
        KeyCode::A,
        KeyState::Pressed,
        Modifiers::default(),
    ));
    inject_key_event_for_tests(key_event(
        KeyCode::Left,
        KeyState::Pressed,
        Modifiers::default(),
    ));

    let first = try_pop_key_event().expect("first gui event");
    let second = try_pop_key_event().expect("second gui event");
    assert_eq!(first.key, KeyCode::A);
    assert_eq!(second.key, KeyCode::Left);

    let mut buf = [0u8; 8];
    let n = read_tty_bytes(&mut buf);
    assert_eq!(&buf[..n], b"a\x1b[D");
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_console_input_hub_vt_switch_hotkey_is_swallowed() {
    reset_input_hub_for_tests();
    init_default();
    switch(0);

    let hotkey = key_event(
        KeyCode::F2,
        KeyState::Pressed,
        Modifiers {
            ctrl: true,
            alt: true,
            ..Modifiers::default()
        },
    );
    inject_key_event_for_tests(hotkey);

    assert_eq!(active_console(), 1);
    assert!(try_pop_key_event().is_none());

    let mut buf = [0u8; 4];
    assert_eq!(read_tty_bytes(&mut buf), 0);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_console_input_hub_drop_counters_increment_when_full() {
    reset_input_hub_for_tests();

    for _ in 0..600 {
        inject_key_event_for_tests(key_event(
            KeyCode::A,
            KeyState::Pressed,
            Modifiers::default(),
        ));
    }

    let (tty_drops_after_keys, gui_drops_after_keys) = dropped_input_counts();
    assert!(gui_drops_after_keys > 0);
    // 600 key presses do not fill the tty buffer yet; queue still may have no drops.
    assert_eq!(tty_drops_after_keys, 0);

    let bytes = alloc::vec![b'x'; 5000];
    inject_tty_bytes_for_tests(&bytes);
    let (tty_drops, gui_drops) = dropped_input_counts();
    assert!(tty_drops > 0);
    assert!(gui_drops >= gui_drops_after_keys);
}
