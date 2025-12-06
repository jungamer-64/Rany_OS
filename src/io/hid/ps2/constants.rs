// ============================================================================
// src/io/hid/ps2/constants.rs - PS/2 Constants
// ============================================================================

/// PS/2コントローラI/Oポート
pub mod ports {
    pub const DATA: u16 = 0x60;     // データポート
    pub const STATUS: u16 = 0x64;   // ステータス（読み取り）
    pub const COMMAND: u16 = 0x64;  // コマンド（書き込み）
}

/// ステータスレジスタビット
pub mod status {
    pub const OUTPUT_FULL: u8 = 0x01;  // 出力バッファフル
    pub const INPUT_FULL: u8 = 0x02;   // 入力バッファフル
    pub const SYSTEM: u8 = 0x04;       // システムフラグ
    pub const COMMAND: u8 = 0x08;      // コマンド/データ
    pub const TIMEOUT: u8 = 0x40;      // タイムアウトエラー
    pub const PARITY: u8 = 0x80;       // パリティエラー
}

/// PS/2コントローラコマンド
pub mod commands {
    pub const READ_CONFIG: u8 = 0x20;   // 設定バイト読み取り
    pub const WRITE_CONFIG: u8 = 0x60;  // 設定バイト書き込み
    pub const DISABLE_PORT2: u8 = 0xA7; // ポート2無効化
    pub const ENABLE_PORT2: u8 = 0xA8;  // ポート2有効化
    pub const TEST_PORT2: u8 = 0xA9;    // ポート2テスト
    pub const SELF_TEST: u8 = 0xAA;     // セルフテスト
    pub const TEST_PORT1: u8 = 0xAB;    // ポート1テスト
    pub const DISABLE_PORT1: u8 = 0xAD; // ポート1無効化
    pub const ENABLE_PORT1: u8 = 0xAE;  // ポート1有効化
    pub const READ_OUTPUT: u8 = 0xD0;   // 出力ポート読み取り
    pub const WRITE_OUTPUT: u8 = 0xD1;  // 出力ポート書き込み
    pub const WRITE_PORT2: u8 = 0xD4;   // ポート2にデータ送信
}

/// キーボードコマンド
pub mod kbd_commands {
    pub const SET_LEDS: u8 = 0xED;          // LED設定
    pub const ECHO: u8 = 0xEE;              // エコー
    pub const GET_SET_SCANCODE: u8 = 0xF0;  // スキャンコードセット取得/設定
    pub const IDENTIFY: u8 = 0xF2;          // デバイス識別
    pub const SET_RATE: u8 = 0xF3;          // タイプマティックレート設定
    pub const ENABLE_SCAN: u8 = 0xF4;       // スキャン有効化
    pub const DISABLE_SCAN: u8 = 0xF5;      // スキャン無効化
    pub const SET_DEFAULTS: u8 = 0xF6;      // デフォルト設定
    pub const RESEND: u8 = 0xFE;            // 再送
    pub const RESET: u8 = 0xFF;             // リセット
}

/// マウスコマンド
pub mod mouse_commands {
    pub const SET_SCALING_1_1: u8 = 0xE6;   // 1:1スケーリング
    pub const SET_SCALING_2_1: u8 = 0xE7;   // 2:1スケーリング
    pub const SET_RESOLUTION: u8 = 0xE8;    // 解像度設定
    pub const GET_STATUS: u8 = 0xE9;        // ステータス取得
    pub const SET_STREAM: u8 = 0xEA;        // ストリームモード
    pub const READ_DATA: u8 = 0xEB;         // データ読み取り
    pub const RESET_WRAP: u8 = 0xEC;        // ラップモードリセット
    pub const SET_WRAP: u8 = 0xEE;          // ラップモード設定
    pub const SET_REMOTE: u8 = 0xF0;        // リモートモード
    pub const GET_ID: u8 = 0xF2;            // デバイスID取得
    pub const SET_SAMPLE_RATE: u8 = 0xF3;   // サンプルレート設定
    pub const ENABLE_DATA: u8 = 0xF4;       // データレポート有効化
    pub const DISABLE_DATA: u8 = 0xF5;      // データレポート無効化
    pub const SET_DEFAULTS: u8 = 0xF6;      // デフォルト設定
    pub const RESEND: u8 = 0xFE;            // 再送
    pub const RESET: u8 = 0xFF;             // リセット
}
