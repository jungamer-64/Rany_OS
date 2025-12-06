// ============================================================================
// src/io/hid/ps2/controller.rs - PS/2 Controller
// ============================================================================

use super::constants::{commands, kbd_commands, mouse_commands, ports, status};

/// PS/2コントローラ
pub struct Ps2Controller {
    /// デュアルチャネルサポート
    dual_channel: bool,
    /// ポート1（キーボード）デバイスタイプ
    pub(crate) port1_type: Option<DeviceType>,
    /// ポート2（マウス）デバイスタイプ
    pub(crate) port2_type: Option<DeviceType>,
    /// 設定バイト
    config: u8,
}

/// PS/2デバイスタイプ
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceType {
    Unknown,
    AtKeyboard,
    MfKeyboard,
    StandardMouse,
    ScrollMouse,
    FiveButtonMouse,
}

impl Ps2Controller {
    /// 新しいPS/2コントローラを作成
    pub fn new() -> Self {
        Self {
            dual_channel: false,
            port1_type: None,
            port2_type: None,
            config: 0,
        }
    }

    /// ステータスレジスタを読み取り
    #[inline]
    fn read_status(&self) -> u8 {
        unsafe {
            let value: u8;
            core::arch::asm!("in al, dx", out("al") value, in("dx") ports::STATUS, options(nomem, nostack));
            value
        }
    }

    /// 出力バッファが空になるまで待機
    ///
    /// # Performance
    /// YIELD_INTERVALごとにspin_loop()を呼び出し、CPUリソースを節約。
    /// これにより、ハイパースレッド対応プロセッサでは他のスレッドに
    /// 実行機会を譲ることができる。
    fn wait_output(&self) -> bool {
        const MAX_ATTEMPTS: u32 = 100_000;
        const YIELD_INTERVAL: u32 = 1000;

        for i in 0..MAX_ATTEMPTS {
            if (self.read_status() & status::OUTPUT_FULL) != 0 {
                return true;
            }
            // ✅ CPUヒント: ビジーループ中のリソース浪費を減らす
            if i % YIELD_INTERVAL == 0 {
                core::hint::spin_loop();
            }
        }
        false
    }

    /// 入力バッファが空になるまで待機
    ///
    /// # Performance
    /// YIELD_INTERVALごとにspin_loop()を呼び出し、CPUリソースを節約。
    fn wait_input(&self) -> bool {
        const MAX_ATTEMPTS: u32 = 100_000;
        const YIELD_INTERVAL: u32 = 1000;

        for i in 0..MAX_ATTEMPTS {
            if (self.read_status() & status::INPUT_FULL) == 0 {
                return true;
            }
            // ✅ CPUヒント: ビジーループ中のリソース浪費を減らす
            if i % YIELD_INTERVAL == 0 {
                core::hint::spin_loop();
            }
        }
        false
    }

    /// データポートから読み取り
    pub(crate) fn read_data(&self) -> u8 {
        self.wait_output();
        unsafe {
            let value: u8;
            core::arch::asm!("in al, dx", out("al") value, in("dx") ports::DATA, options(nomem, nostack));
            value
        }
    }

    /// データポートに書き込み
    fn write_data(&self, value: u8) {
        self.wait_input();
        unsafe {
            core::arch::asm!("out dx, al", in("dx") ports::DATA, in("al") value, options(nomem, nostack));
        }
    }

    /// コマンドポートに書き込み
    fn write_command(&self, cmd: u8) {
        self.wait_input();
        unsafe {
            core::arch::asm!("out dx, al", in("dx") ports::COMMAND, in("al") cmd, options(nomem, nostack));
        }
    }

    /// 設定バイトを読み取り
    fn read_config(&mut self) -> u8 {
        self.write_command(commands::READ_CONFIG);
        let config = self.read_data();
        self.config = config;
        config
    }

    /// 設定バイトを書き込み
    fn write_config(&mut self, config: u8) {
        self.write_command(commands::WRITE_CONFIG);
        self.write_data(config);
        self.config = config;
    }

    /// セルフテスト
    fn self_test(&self) -> bool {
        self.write_command(commands::SELF_TEST);
        self.wait_output();
        self.read_data() == 0x55
    }

    /// ポート1テスト
    fn test_port1(&self) -> bool {
        self.write_command(commands::TEST_PORT1);
        self.wait_output();
        self.read_data() == 0x00
    }

    /// ポート2テスト
    fn test_port2(&self) -> bool {
        self.write_command(commands::TEST_PORT2);
        self.wait_output();
        self.read_data() == 0x00
    }

    /// ポート1（キーボード）にコマンド送信
    pub(crate) fn send_port1(&self, cmd: u8) -> Option<u8> {
        self.write_data(cmd);
        self.wait_output();
        let response = self.read_data();
        if response == 0xFA {
            // ACK
            Some(response)
        } else if response == 0xFE {
            // RESEND
            // リトライ
            self.write_data(cmd);
            self.wait_output();
            Some(self.read_data())
        } else {
            Some(response)
        }
    }

    /// ポート2（マウス）にコマンド送信
    pub(crate) fn send_port2(&self, cmd: u8) -> Option<u8> {
        self.write_command(commands::WRITE_PORT2);
        self.write_data(cmd);
        self.wait_output();
        let response = self.read_data();
        if response == 0xFA {
            Some(response)
        } else if response == 0xFE {
            self.write_command(commands::WRITE_PORT2);
            self.write_data(cmd);
            self.wait_output();
            Some(self.read_data())
        } else {
            Some(response)
        }
    }

    /// デバイス識別
    #[allow(dead_code)]
    fn identify_device(&self, port2: bool) -> Option<DeviceType> {
        let send = if port2 {
            Self::send_port2
        } else {
            Self::send_port1
        };

        // IDENTIFYコマンド送信
        if send(self, kbd_commands::IDENTIFY) != Some(0xFA) {
            return None;
        }

        // 最初のバイトを読み取り
        if !self.wait_output() {
            return None;
        }
        let byte1 = self.read_data();

        // デバイスタイプを判定
        match byte1 {
            0x00 => Some(DeviceType::StandardMouse),
            0x03 => Some(DeviceType::ScrollMouse),
            0x04 => Some(DeviceType::FiveButtonMouse),
            0xAB => {
                // キーボード - 2バイト目を読み取り
                if self.wait_output() {
                    let byte2 = self.read_data();
                    match byte2 {
                        0x41 | 0xC1 => Some(DeviceType::MfKeyboard),
                        0x83 => Some(DeviceType::MfKeyboard),
                        _ => Some(DeviceType::AtKeyboard),
                    }
                } else {
                    Some(DeviceType::AtKeyboard)
                }
            }
            _ => Some(DeviceType::Unknown),
        }
    }

    /// キーボードを初期化
    fn init_keyboard(&self) -> bool {
        // リセット
        if self.send_port1(kbd_commands::RESET) != Some(0xFA) {
            return false;
        }
        // BAT完了を待機
        self.wait_output();
        if self.read_data() != 0xAA {
            return false;
        }

        // スキャンコードセット2を設定
        self.send_port1(kbd_commands::GET_SET_SCANCODE);
        self.send_port1(0x02);

        // スキャン有効化
        self.send_port1(kbd_commands::ENABLE_SCAN);

        true
    }

    /// マウスを初期化
    fn init_mouse(&self) -> Option<DeviceType> {
        // リセット
        if self.send_port2(mouse_commands::RESET) != Some(0xFA) {
            return None;
        }
        // BAT完了を待機
        self.wait_output();
        if self.read_data() != 0xAA {
            return None;
        }
        // デバイスIDを読み飛ばし
        self.wait_output();
        let _ = self.read_data();

        // IntelliMouseプロトコルの有効化を試行
        self.send_port2(mouse_commands::SET_SAMPLE_RATE);
        self.send_port2(200);
        self.send_port2(mouse_commands::SET_SAMPLE_RATE);
        self.send_port2(100);
        self.send_port2(mouse_commands::SET_SAMPLE_RATE);
        self.send_port2(80);

        // デバイスIDを確認
        self.send_port2(mouse_commands::GET_ID);
        self.wait_output();
        let device_id = self.read_data();

        let device_type = match device_id {
            0x00 => DeviceType::StandardMouse,
            0x03 => {
                // 5ボタンマウスの有効化を試行
                self.send_port2(mouse_commands::SET_SAMPLE_RATE);
                self.send_port2(200);
                self.send_port2(mouse_commands::SET_SAMPLE_RATE);
                self.send_port2(200);
                self.send_port2(mouse_commands::SET_SAMPLE_RATE);
                self.send_port2(80);

                self.send_port2(mouse_commands::GET_ID);
                self.wait_output();
                let device_id2 = self.read_data();

                if device_id2 == 0x04 {
                    DeviceType::FiveButtonMouse
                } else {
                    DeviceType::ScrollMouse
                }
            }
            0x04 => DeviceType::FiveButtonMouse,
            _ => DeviceType::Unknown,
        };

        // データレポート有効化
        self.send_port2(mouse_commands::ENABLE_DATA);

        Some(device_type)
    }

    /// コントローラを初期化
    pub fn initialize(&mut self) -> bool {
        // 両ポートを無効化
        self.write_command(commands::DISABLE_PORT1);
        self.write_command(commands::DISABLE_PORT2);

        // 出力バッファをフラッシュ
        while (self.read_status() & status::OUTPUT_FULL) != 0 {
            let _ = self.read_data();
        }

        // 設定バイトを読み取り
        let mut config = self.read_config();

        // デュアルチャネルかどうかを確認
        self.dual_channel = (config & 0x20) != 0;

        // 割り込みを無効化、変換を無効化
        config &= !0x43;
        self.write_config(config);

        // セルフテスト
        if !self.self_test() {
            return false;
        }

        // 設定を再書き込み（セルフテストでリセットされる可能性）
        self.write_config(config);

        // デュアルチャネルを確認
        if self.dual_channel {
            self.write_command(commands::ENABLE_PORT2);
            let config2 = self.read_config();
            self.dual_channel = (config2 & 0x20) == 0;
            if self.dual_channel {
                self.write_command(commands::DISABLE_PORT2);
            }
        }

        // ポートテスト
        let port1_ok = self.test_port1();
        let port2_ok = self.dual_channel && self.test_port2();

        // ポートを有効化
        if port1_ok {
            self.write_command(commands::ENABLE_PORT1);
            config |= 0x01; // ポート1割り込み有効
        }

        if port2_ok {
            self.write_command(commands::ENABLE_PORT2);
            config |= 0x02; // ポート2割り込み有効
        }

        self.write_config(config);

        // デバイスを初期化
        if port1_ok {
            if self.init_keyboard() {
                self.port1_type = Some(DeviceType::MfKeyboard);
            }
        }

        if port2_ok {
            self.port2_type = self.init_mouse();
        }

        true
    }

    /// キーボードLEDを設定
    pub fn set_keyboard_leds(&self, scroll: bool, num: bool, caps: bool) {
        let leds = (scroll as u8) | ((num as u8) << 1) | ((caps as u8) << 2);
        self.send_port1(kbd_commands::SET_LEDS);
        self.send_port1(leds);
    }
}

impl Default for Ps2Controller {
    fn default() -> Self {
        Self::new()
    }
}
