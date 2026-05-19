// ============================================================================
// src/io/hid/ps2/constants.rs - PS/2 Constants
// ============================================================================

/// PS/2コントローラI/Oポート
pub mod ports {
    pub const DATA: u16 = 0x60; // データポート
    pub const STATUS: u16 = 0x64; // ステータス（読み取り）
    pub const COMMAND: u16 = 0x64; // コマンド（書き込み）
}

/// ステータスレジスタビット
pub mod status {
    pub const OUTPUT_FULL: u8 = 0x01; // 出力バッファフル
    pub const INPUT_FULL: u8 = 0x02; // 入力バッファフル
    pub const SYSTEM: u8 = 0x04; // システムフラグ
    pub const COMMAND: u8 = 0x08; // コマンド/データ
    pub const TIMEOUT: u8 = 0x40; // タイムアウトエラー
    pub const PARITY: u8 = 0x80; // パリティエラー
}

/// PS/2コントローラコマンド
pub mod commands {
    pub const READ_CONFIG: u8 = 0x20; // 設定バイト読み取り
    pub const WRITE_CONFIG: u8 = 0x60; // 設定バイト書き込み
    pub const DISABLE_PORT2: u8 = 0xA7; // ポート2無効化
    pub const ENABLE_PORT2: u8 = 0xA8; // ポート2有効化
    pub const TEST_PORT2: u8 = 0xA9; // ポート2テスト
    pub const SELF_TEST: u8 = 0xAA; // セルフテスト
    pub const TEST_PORT1: u8 = 0xAB; // ポート1テスト
    pub const DISABLE_PORT1: u8 = 0xAD; // ポート1無効化
    pub const ENABLE_PORT1: u8 = 0xAE; // ポート1有効化
    pub const READ_OUTPUT: u8 = 0xD0; // 出力ポート読み取り
    pub const WRITE_OUTPUT: u8 = 0xD1; // 出力ポート書き込み
    pub const WRITE_PORT2: u8 = 0xD4; // ポート2にデータ送信
}

/// キーボードコマンド
pub mod kbd_commands {
    pub const SET_LEDS: u8 = 0xED; // LED設定
    pub const GET_SET_SCANCODE: u8 = 0xF0; // スキャンコードセット取得/設定
    pub const ENABLE_SCAN: u8 = 0xF4; // スキャン有効化
    pub const RESET: u8 = 0xFF; // リセット
}

/// マウスコマンド
pub mod mouse_commands {
    pub const GET_ID: u8 = 0xF2; // デバイスID取得
    pub const SET_SAMPLE_RATE: u8 = 0xF3; // サンプルレート設定
    pub const ENABLE_DATA: u8 = 0xF4; // データレポート有効化
    pub const RESET: u8 = 0xFF; // リセット
}
