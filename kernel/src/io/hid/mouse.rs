// ============================================================================
// src/io/hid/mouse.rs - PS/2 Mouse Driver
// ============================================================================
//!
//! # PS/2マウスドライバ
//!
//! PS/2マウスからの入力を処理するドライバ。
//!
//! ## 機能
//! - PS/2マウス入力 (標準3バイトパケット)
//! - マウスイベントキュー
//! - 割り込みコンテキストでの安全な処理
//!
//! ## エラーハンドリング
//! 初期化処理は`Result<(), MouseInitError>`を返し、
//! エラーの種類を明確に分類します。

#![allow(dead_code)]  // API全体を提供するため、未使用警告を抑制

use alloc::collections::VecDeque;
use core::fmt;
use spin::Mutex;
use x86_64::instructions::port::Port;

// ============================================================================
// Error Types
// ============================================================================

/// マウス初期化エラー
///
/// 初期化処理中に発生しうるエラーを分類。
/// 各エラーにはリカバリーのヒントを含む。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseInitError {
    /// SET_DEFAULTS (0xF6) コマンドが失敗
    ///
    /// 考えられる原因:
    /// - マウスが物理的に接続されていない
    /// - PS/2コントローラが無効化されている
    /// - マウスが応答しない（故障）
    SetDefaultsFailed,

    /// ENABLE_DATA (0xF4) コマンドが失敗
    ///
    /// 考えられる原因:
    /// - SET_DEFAULTS後の状態異常
    /// - マウスがデータストリーミングを拒否
    EnableDataFailed,

    /// IRQ12有効化が失敗
    ///
    /// 考えられる原因:
    /// - PS/2コントローラの設定書き込みが反映されない
    /// - コントローラがロックされている
    IrqEnableFailed,

    /// タイムアウト
    ///
    /// 指定された回数内にマウスからの応答がない。
    /// 最大待機回数: 100,000回
    Timeout,
}

impl fmt::Display for MouseInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SetDefaultsFailed => write!(f, "mouse initialization failed"),
            Self::EnableDataFailed => write!(f, "mouse data streaming unavailable"),
            Self::IrqEnableFailed => write!(f, "mouse interrupt enable failed"),
            Self::Timeout => write!(f, "mouse not responding"),
        }
    }
}

// ============================================================================
// Constants
// ============================================================================

/// PS/2データポート
const PS2_DATA_PORT: u16 = 0x60;
/// PS/2ステータス/コマンドポート
const PS2_STATUS_PORT: u16 = 0x64;

/// コントローラコマンド
const CMD_READ_CONFIG: u8 = 0x20;
const CMD_WRITE_CONFIG: u8 = 0x60;
const CMD_ENABLE_AUX: u8 = 0xA8;      // マウス有効化
const CMD_WRITE_TO_AUX: u8 = 0xD4;    // 次のバイトをマウスへ送信

/// マウスコマンド
const MOUSE_CMD_SET_DEFAULTS: u8 = 0xF6;
const MOUSE_CMD_ENABLE_DATA: u8 = 0xF4;

/// 応答
const ACK: u8 = 0xFA;

/// イベントキューの最大サイズ
const MAX_EVENT_QUEUE_SIZE: usize = 128;

// ============================================================================
// Mouse Types
// ============================================================================

/// マウスボタン
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

/// マウスイベント
#[derive(Debug, Clone, Copy)]
pub struct MouseEvent {
    /// X方向の移動量
    pub dx: i32,
    /// Y方向の移動量
    pub dy: i32,
    /// 左ボタンが押されているか
    pub left_down: bool,
    /// 右ボタンが押されているか
    pub right_down: bool,
    /// 中ボタンが押されているか
    pub middle_down: bool,
}

impl MouseEvent {
    /// いずれかのボタンが押されているか
    pub fn any_button(&self) -> bool {
        self.left_down || self.right_down || self.middle_down
    }
    
    /// 移動があるか
    pub fn has_movement(&self) -> bool {
        self.dx != 0 || self.dy != 0
    }
}

// ============================================================================
// Helper Functions (Port I/O)
// ============================================================================

/// ステータスレジスタを読み取り、書き込み準備ができるまで待機
fn wait_for_write(status_port: &mut Port<u8>) {
    for _ in 0..100000 {
        let status = unsafe { status_port.read() };
        if status & 0x02 == 0 {
            return; // Input buffer empty
        }
        core::hint::spin_loop();
    }
}

// ============================================================================
// Mouse Driver
// ============================================================================

/// PS/2 マウスドライバ
pub struct Mouse {
    /// データポート
    data_port: Port<u8>,
    /// ステータスポート
    status_port: Port<u8>,
    /// パケットバッファ（標準PS/2マウスは3バイト）
    packet: [u8; 3],
    /// パケットインデックス
    packet_index: u8,
    /// イベントキュー
    event_queue: VecDeque<MouseEvent>,
    /// 前回のボタン状態（クリック検出用）
    prev_buttons: u8,
    /// マウスが初期化されているか
    initialized: bool,
}

impl Mouse {
    /// 新しいマウスドライバを作成
    pub const fn new() -> Self {
        Self {
            data_port: Port::new(PS2_DATA_PORT),
            status_port: Port::new(PS2_STATUS_PORT),
            packet: [0; 3],
            packet_index: 0,
            event_queue: VecDeque::new(),
            prev_buttons: 0,
            initialized: false,
        }
    }

    /// マウスの初期化
    ///
    /// # Returns
    /// - `Ok(())` - 初期化成功
    /// - `Err(MouseInitError)` - 初期化失敗（原因はエラー型を参照）
    ///
    /// # Note
    /// この関数は割り込みが有効な状態では呼び出さないでください。
    /// I/Oタイムアウトループが割り込みにより中断される可能性があります。
    pub fn init(&mut self) -> Result<(), MouseInitError> {
        // 1. Auxiliary Device (マウス) を有効化
        self.write_controller_command(CMD_ENABLE_AUX);

        // 2. コントローラ設定バイトを読み取り
        self.write_controller_command(CMD_READ_CONFIG);
        let mut config = self.read_data_timeout().ok_or(MouseInitError::Timeout)?;
        
        // IRQ12を有効化 (Bit 1)
        // マウスクロックを有効化 (Bit 5をクリア)
        config |= 0x02;   // Enable IRQ12
        config &= !0x20;  // Enable mouse clock
        
        // 設定を書き戻し
        self.write_controller_command(CMD_WRITE_CONFIG);
        self.write_data(config);

        // ✅ 設定が正しく書き込まれたか検証
        self.write_controller_command(CMD_READ_CONFIG);
        let actual_config = self.read_data_timeout().ok_or(MouseInitError::Timeout)?;
        if (actual_config & 0x02) == 0 {
            // IRQ12が有効化されていない
            return Err(MouseInitError::IrqEnableFailed);
        }

        // 3. マウスをデフォルト設定にリセット
        self.write_mouse_command(MOUSE_CMD_SET_DEFAULTS)
            .map_err(|()| MouseInitError::SetDefaultsFailed)?;

        // 4. データストリーミング開始
        self.write_mouse_command(MOUSE_CMD_ENABLE_DATA)
            .map_err(|()| MouseInitError::EnableDataFailed)?;

        self.initialized = true;
        crate::log!("[HID] Mouse initialized (IRQ12 enabled)\n");
        Ok(())
    }

    /// PS/2コントローラへのコマンド書き込み
    fn write_controller_command(&mut self, cmd: u8) {
        wait_for_write(&mut self.status_port);
        unsafe {
            self.status_port.write(cmd);
        }
    }

    /// PS/2データポートへの書き込み
    fn write_data(&mut self, data: u8) {
        wait_for_write(&mut self.status_port);
        unsafe {
            self.data_port.write(data);
        }
    }

    /// PS/2データポートからの読み込み（タイムアウト付き）
    fn read_data_timeout(&mut self) -> Option<u8> {
        for _ in 0..100000 {
            let status = unsafe { self.status_port.read() };
            if status & 0x01 != 0 {
                return Some(unsafe { self.data_port.read() });
            }
            core::hint::spin_loop();
        }
        None
    }

    /// マウスデバイスへのコマンド送信（0xD4経由）
    fn write_mouse_command(&mut self, cmd: u8) -> Result<u8, ()> {
        // コントローラに「次はマウスへのデータだ」と伝える
        self.write_controller_command(CMD_WRITE_TO_AUX);
        // データポートにコマンドを書く
        self.write_data(cmd);
        
        // ACKを待つ
        if let Some(response) = self.read_data_timeout() {
            if response == ACK {
                return Ok(response);
            }
        }
        Err(())
    }

    /// マウスからのデータ（1バイト）を処理
    pub fn process_packet(&mut self, data: u8) {
        if !self.initialized {
            return;
        }

        // パケットの最初のバイトは常にBit 3が1であるべき
        if self.packet_index == 0 && (data & 0x08) == 0 {
            // 同期ズレの可能性、リセット
            return;
        }

        self.packet[self.packet_index as usize] = data;
        self.packet_index += 1;

        // 3バイト揃ったらパケット完了
        if self.packet_index == 3 {
            self.packet_index = 0;
            self.finalize_packet();
        }
    }

    /// 受信した3バイトパケットを解析してイベント生成
    fn finalize_packet(&mut self) {
        let flags = self.packet[0];
        let x_raw = self.packet[1];
        let y_raw = self.packet[2];

        // オーバーフローチェック
        let x_overflow = (flags & 0x40) != 0;
        let y_overflow = (flags & 0x80) != 0;
        
        if x_overflow || y_overflow {
            return; // 動きが大きすぎる場合は無視
        }

        // 移動量の計算（9bit符号付き整数）
        let mut dx = x_raw as i16;
        let mut dy = y_raw as i16;

        // 符号拡張
        if (flags & 0x10) != 0 {
            dx |= !0xFF; // X Sign extension
        }
        if (flags & 0x20) != 0 {
            dy |= !0xFF; // Y Sign extension
        }

        // ボタン状態
        let left = (flags & 0x01) != 0;
        let right = (flags & 0x02) != 0;
        let middle = (flags & 0x04) != 0;

        let event = MouseEvent {
            dx: dx as i32,
            dy: -(dy as i32), // Y軸を反転（画面座標系に合わせる）
            left_down: left,
            right_down: right,
            middle_down: middle,
        };

        // ボタン状態を更新
        self.prev_buttons = flags & 0x07;

        // バッファ溢れ防止
        if self.event_queue.len() < MAX_EVENT_QUEUE_SIZE {
            self.event_queue.push_back(event);
        }
    }

    /// イベントを取得
    pub fn poll_event(&mut self) -> Option<MouseEvent> {
        self.event_queue.pop_front()
    }

    /// キューにイベントがあるか
    pub fn has_event(&self) -> bool {
        !self.event_queue.is_empty()
    }
    
    /// 初期化されているか
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

// ============================================================================
// Global State
// ============================================================================

/// グローバルマウス
static MOUSE: Mutex<Mouse> = Mutex::new(Mouse::new());

// ============================================================================
// Public API - Initialization
// ============================================================================

/// マウスを初期化
///
/// # Returns
/// - `Ok(())` - 初期化成功
/// - `Err(MouseInitError)` - 初期化失敗
///
/// # Example
/// ```ignore
/// match mouse::init() {
///     Ok(()) => log!("Mouse ready"),
///     Err(e) => log!("Mouse init failed: {}", e),
/// }
/// ```
pub fn init() -> Result<(), MouseInitError> {
    MOUSE.lock().init()
}

// ============================================================================
// Public API - Mouse (割り込みハンドラ用)
// ============================================================================

/// マウスパケットバイトを処理（IRQ12割り込みハンドラから呼ばれる）
/// try_lockを使用してデッドロックを防止
pub fn handle_mouse_packet(data: u8) {
    if let Some(mut guard) = MOUSE.try_lock() {
        guard.process_packet(data);
    }
}

// ============================================================================
// Public API - Mouse (ユーザーコード用)
// ============================================================================

/// マウスイベントを取得（割り込みを無効にして実行）
pub fn poll_mouse_event() -> Option<MouseEvent> {
    x86_64::instructions::interrupts::without_interrupts(|| {
        MOUSE.lock().poll_event()
    })
}

/// マウスイベントがあるか（割り込みを無効にして実行）
pub fn has_mouse_event() -> bool {
    x86_64::instructions::interrupts::without_interrupts(|| {
        MOUSE.lock().has_event()
    })
}

/// マウスが初期化されているか
pub fn is_mouse_initialized() -> bool {
    x86_64::instructions::interrupts::without_interrupts(|| {
        MOUSE.lock().is_initialized()
    })
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// テスト用のマウスインスタンスを作成
    fn test_mouse() -> Mouse {
        Mouse::new()
    }

    // =========================================================================
    // パケット同期回復テスト
    // =========================================================================

    #[test]
    fn test_packet_sync_recovery_invalid_first_byte() {
        let mut mouse = test_mouse();
        mouse.initialized = true;

        // ビット3が0のパケットは無視される（同期外れ）
        mouse.process_packet(0x00);
        assert_eq!(mouse.packet_index, 0, "Invalid packet should be ignored");

        // ビット3が1の有効なパケット開始
        mouse.process_packet(0x08);
        assert_eq!(mouse.packet_index, 1, "Valid packet should be accepted");
    }

    #[test]
    fn test_packet_sync_recovery_multiple_invalid() {
        let mut mouse = test_mouse();
        mouse.initialized = true;

        // 複数の無効パケットを送信
        for i in 0..5 {
            mouse.process_packet(i & 0x07);  // ビット3常に0
        }
        assert_eq!(mouse.packet_index, 0, "All invalid packets should be ignored");

        // 有効なパケット開始後に続ける
        mouse.process_packet(0x08);  // 1バイト目
        assert_eq!(mouse.packet_index, 1);
        mouse.process_packet(0x10);  // 2バイト目
        assert_eq!(mouse.packet_index, 2);
        mouse.process_packet(0x20);  // 3バイト目（完了）
        assert_eq!(mouse.packet_index, 0, "Packet should complete and reset");
    }

    // =========================================================================
    // 移動量符号拡張テスト
    // =========================================================================

    #[test]
    fn test_movement_positive() {
        let mut mouse = test_mouse();
        mouse.initialized = true;

        // 正の移動: dx=10, dy=20
        // flags: 0x08 (ビット3=1, X/Y符号=0)
        mouse.process_packet(0x08);
        mouse.process_packet(10);   // X
        mouse.process_packet(20);   // Y

        let event = mouse.poll_event().expect("Event should be generated");
        assert_eq!(event.dx, 10);
        assert_eq!(event.dy, -20);  // Y軸は反転される
    }

    #[test]
    fn test_movement_negative_x() {
        let mut mouse = test_mouse();
        mouse.initialized = true;

        // 負のX移動: dx=-5 (0xFB in 8-bit signed)
        // flags: 0x18 (ビット3=1, X符号=1)
        mouse.process_packet(0x18);  // X符号ビット=1
        mouse.process_packet(0xFB); // -5 in 8-bit
        mouse.process_packet(0);

        let event = mouse.poll_event().expect("Event should be generated");
        assert_eq!(event.dx, -5);
        assert_eq!(event.dy, 0);
    }

    #[test]
    fn test_movement_negative_y() {
        let mut mouse = test_mouse();
        mouse.initialized = true;

        // 負のY移動: dy=-10 (0xF6 in 8-bit signed)
        // flags: 0x28 (ビット3=1, Y符号=1)
        mouse.process_packet(0x28);  // Y符号ビット=1
        mouse.process_packet(0);
        mouse.process_packet(0xF6); // -10 in 8-bit

        let event = mouse.poll_event().expect("Event should be generated");
        assert_eq!(event.dx, 0);
        // Y軸反転: -(-10) = 10
        assert_eq!(event.dy, 10);
    }

    #[test]
    fn test_movement_both_negative() {
        let mut mouse = test_mouse();
        mouse.initialized = true;

        // 両方負: dx=-1, dy=-1
        // flags: 0x38 (ビット3=1, X符号=1, Y符号=1)
        mouse.process_packet(0x38);
        mouse.process_packet(0xFF); // -1
        mouse.process_packet(0xFF); // -1

        let event = mouse.poll_event().expect("Event should be generated");
        assert_eq!(event.dx, -1);
        assert_eq!(event.dy, 1);  // Y軸反転
    }

    // =========================================================================
    // ボタン状態テスト
    // =========================================================================

    #[test]
    fn test_button_left_pressed() {
        let mut mouse = test_mouse();
        mouse.initialized = true;

        // 左ボタン押下: flags bit 0 = 1
        mouse.process_packet(0x09);  // 0x08 | 0x01
        mouse.process_packet(0);
        mouse.process_packet(0);

        let event = mouse.poll_event().expect("Event should be generated");
        assert!(event.left_down);
        assert!(!event.right_down);
        assert!(!event.middle_down);
    }

    #[test]
    fn test_button_right_pressed() {
        let mut mouse = test_mouse();
        mouse.initialized = true;

        // 右ボタン押下: flags bit 1 = 1
        mouse.process_packet(0x0A);  // 0x08 | 0x02
        mouse.process_packet(0);
        mouse.process_packet(0);

        let event = mouse.poll_event().expect("Event should be generated");
        assert!(!event.left_down);
        assert!(event.right_down);
        assert!(!event.middle_down);
    }

    #[test]
    fn test_button_middle_pressed() {
        let mut mouse = test_mouse();
        mouse.initialized = true;

        // 中ボタン押下: flags bit 2 = 1
        mouse.process_packet(0x0C);  // 0x08 | 0x04
        mouse.process_packet(0);
        mouse.process_packet(0);

        let event = mouse.poll_event().expect("Event should be generated");
        assert!(!event.left_down);
        assert!(!event.right_down);
        assert!(event.middle_down);
    }

    #[test]
    fn test_button_all_pressed() {
        let mut mouse = test_mouse();
        mouse.initialized = true;

        // 全ボタン押下: flags bits 0,1,2 = 1
        mouse.process_packet(0x0F);  // 0x08 | 0x07
        mouse.process_packet(0);
        mouse.process_packet(0);

        let event = mouse.poll_event().expect("Event should be generated");
        assert!(event.left_down);
        assert!(event.right_down);
        assert!(event.middle_down);
        assert!(event.any_button());
    }

    // =========================================================================
    // オーバーフローテスト
    // =========================================================================

    #[test]
    fn test_overflow_ignored() {
        let mut mouse = test_mouse();
        mouse.initialized = true;

        // Xオーバーフローフラグ (bit 6)
        mouse.process_packet(0x48);  // 0x08 | 0x40
        mouse.process_packet(0xFF);
        mouse.process_packet(0);

        assert!(mouse.poll_event().is_none(), "Overflow packet should be ignored");
    }

    #[test]
    fn test_y_overflow_ignored() {
        let mut mouse = test_mouse();
        mouse.initialized = true;

        // Yオーバーフローフラグ (bit 7)
        mouse.process_packet(0x88);  // 0x08 | 0x80
        mouse.process_packet(0);
        mouse.process_packet(0xFF);

        assert!(mouse.poll_event().is_none(), "Overflow packet should be ignored");
    }

    // =========================================================================
    // 未初期化状態テスト
    // =========================================================================

    #[test]
    fn test_uninitialized_ignores_packets() {
        let mut mouse = test_mouse();
        // initialized = false (デフォルト)

        mouse.process_packet(0x08);
        mouse.process_packet(10);
        mouse.process_packet(20);

        assert!(mouse.poll_event().is_none(), "Uninitialized mouse should ignore packets");
    }

    // =========================================================================
    // MouseEventヘルパーテスト
    // =========================================================================

    #[test]
    fn test_mouse_event_has_movement() {
        let event_with_movement = MouseEvent {
            dx: 10,
            dy: 0,
            left_down: false,
            right_down: false,
            middle_down: false,
        };
        assert!(event_with_movement.has_movement());

        let event_no_movement = MouseEvent {
            dx: 0,
            dy: 0,
            left_down: true,
            right_down: false,
            middle_down: false,
        };
        assert!(!event_no_movement.has_movement());
    }

    #[test]
    fn test_mouse_event_any_button() {
        let event_no_buttons = MouseEvent {
            dx: 0,
            dy: 0,
            left_down: false,
            right_down: false,
            middle_down: false,
        };
        assert!(!event_no_buttons.any_button());

        let event_left = MouseEvent {
            dx: 0,
            dy: 0,
            left_down: true,
            right_down: false,
            middle_down: false,
        };
        assert!(event_left.any_button());
    }

    // =========================================================================
    // エラー型テスト
    // =========================================================================

    #[test]
    fn test_mouse_init_error_display() {
        assert_eq!(
            format!("{}", MouseInitError::SetDefaultsFailed),
            "mouse initialization failed"
        );
        assert_eq!(
            format!("{}", MouseInitError::EnableDataFailed),
            "mouse data streaming unavailable"
        );
        assert_eq!(
            format!("{}", MouseInitError::IrqEnableFailed),
            "mouse interrupt enable failed"
        );
        assert_eq!(
            format!("{}", MouseInitError::Timeout),
            "mouse not responding"
        );
    }
}