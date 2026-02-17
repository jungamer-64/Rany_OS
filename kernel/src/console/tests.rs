use super::*;

#[test_case]
fn test_ansi_color_rgb() {
    assert_eq!(AnsiColor::Black.to_rgb(), 0x000000);
    assert_eq!(AnsiColor::White.to_rgb(), 0xAAAAAA);
    assert_eq!(AnsiColor::BrightWhite.to_rgb(), 0xFFFFFF);
}

#[test_case]
fn test_terminal_buffer() {
    let mut buffer = TerminalBuffer::new(80, 25);
    buffer.write_str("Hello, World!");
    assert_eq!(buffer.cursor(), (13, 0));

    buffer.write_char('\n');
    assert_eq!(buffer.cursor(), (0, 1));
}

#[test_case]
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

#[test_case]
fn test_virtual_console() {
    let mut vc = VirtualConsole::new(0, 80, 25);
    vc.write("Hello\n");
    assert_eq!(vc.buffer().cursor(), (0, 1));

    // ANSIカラー
    vc.write("\x1b[31mRed\x1b[0m");
}
