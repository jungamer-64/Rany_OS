// ============================================================================
// src/io/usb/xhci/context.rs - xHCI Device Context Structures
// ============================================================================
//!
//! xHCI デバイスコンテキスト関連の構造体定義。
//!
//! ## コンテキスト構造
//! - SlotContext: スロット状態（デバイス接続情報）
//! - EndpointContext: エンドポイント状態（転送設定）
//! - DeviceContext: デバイス全体のコンテキスト
//! - InputContext: コマンド用の入力コンテキスト
use crate::UsbSpeed;

// ============================================================================
// Slot Context
// ============================================================================

/// スロットコンテキスト (32バイト)
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default)]
pub struct SlotContext {
    /// ルートハブポート番号、速度など
    pub route_string_and_speed: u32,
    /// 最大終了レイテンシなど
    pub latency_and_ports: u32,
    /// 親ハブスロットID、TTポート番号
    pub tt_info: u32,
    /// デバイス状態、デバイスアドレス
    pub state_and_address: u32,
    /// 予約
    pub reserved: [u32; 4],
}

impl SlotContext {
    /// スロット状態を取得
    pub fn slot_state(&self) -> u8 {
        ((self.state_and_address >> 27) & 0x1F) as u8
    }

    /// デバイスアドレスを取得
    pub fn device_address(&self) -> u8 {
        (self.state_and_address & 0xFF) as u8
    }

    /// 設定
    pub fn set_context(
        &mut self,
        speed: UsbSpeed,
        route_string: u32,
        root_port: u8,
        context_entries: u8,
    ) {
        self.route_string_and_speed = (route_string & 0xFFFFF)
            | ((speed.to_slot_speed() as u32) << 20)
            | ((context_entries as u32) << 27);

        self.latency_and_ports = (root_port as u32) << 16;
    }

    /// TT情報を設定 (High Speed Hub ビハインドのFS/LSデバイス用)
    pub fn set_tt(&mut self, parent_slot_id: u8, tt_port: u8) {
        // TT Hub Slot ID (Bits 0-7), TT Port Number (Bits 8-15)
        self.tt_info = (parent_slot_id as u32) | ((tt_port as u32) << 8);
    }

    /// 親のルートストリングとポート番号から新しいルートストリングを計算
    pub fn append_route(parent_route: u32, port: u8) -> u32 {
        if parent_route == 0 {
            // Tier 2 (Connected to Root Hub's child hub)
            // Or rather, the device is Tier 3.
            // Parent is Tier 2 (Route=0).
            return port as u32;
        }

        // Find the first empty (0) nibble
        for i in 0..4 {
            let shift = (i + 1) * 4;
            if (parent_route >> shift) & 0xF == 0 {
                return parent_route | ((port as u32) << shift);
            }
        }

        // Overflow (Max Tier 7 reached or error)
        parent_route
    }
}

// ============================================================================
// Endpoint Context
// ============================================================================

/// エンドポイントコンテキスト (32バイト)
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default)]
pub struct EndpointContext {
    /// エンドポイント状態、タイプなど
    pub ep_state_and_type: u32,
    /// 最大パケットサイズ、バーストサイズなど
    pub max_packet_and_burst: u32,
    /// TRデキューポインタ
    pub tr_dequeue_ptr: u64,
    /// 平均TRB長など
    pub average_trb_length: u32,
    /// 予約
    pub reserved: [u32; 3],
}

impl EndpointContext {
    /// 設定
    pub fn set_context(
        &mut self,
        ep_type: u8,
        max_packet_size: u16,
        max_burst_size: u8,
        tr_dequeue_ptr: u64,
        interval: u8,
        error_count: u8,
    ) {
        self.ep_state_and_type =
            ((ep_type as u32) << 3) | ((error_count as u32) << 1) | ((interval as u32) << 16);

        self.max_packet_and_burst = (max_packet_size as u32) | ((max_burst_size as u32) << 8);

        // DCS (Dequeue Cycle State) = 1
        self.tr_dequeue_ptr = tr_dequeue_ptr | 1;

        self.average_trb_length = 8; // デフォルト値
    }
}

// ============================================================================
// Device Context
// ============================================================================

/// デバイスコンテキスト
#[repr(C, align(64))]
pub struct DeviceContext {
    pub slot: SlotContext,
    pub endpoints: [EndpointContext; 31],
}

// ============================================================================
// Input Context
// ============================================================================

/// 入力コンテキスト
#[repr(C, align(64))]
pub struct InputContext {
    /// 入力コントロールコンテキスト
    pub input_control: InputControlContext,
    /// スロットコンテキスト
    pub slot: SlotContext,
    /// エンドポイントコンテキスト
    pub endpoints: [EndpointContext; 31],
}

/// 入力コントロールコンテキスト
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default)]
pub struct InputControlContext {
    /// ドロップコンテキストフラグ
    pub drop_flags: u32,
    /// 追加コンテキストフラグ
    pub add_flags: u32,
    /// 予約
    pub reserved: [u32; 6],
}

impl InputControlContext {
    /// Add Context フラグを設定
    ///
    /// ビット0: スロットコンテキスト
    /// ビット1-31: エンドポイントコンテキスト (DCI 1-31)
    pub fn set_add_context(&mut self, slot: bool, endpoints: u32) {
        self.add_flags = if slot { 1 } else { 0 } | (endpoints << 1);
    }

    /// Drop Context フラグを設定
    pub fn set_drop_context(&mut self, endpoints: u32) {
        self.drop_flags = endpoints << 1;
    }

    /// スロットとエンドポイント0を追加対象に設定
    pub fn set_for_address_device(&mut self) {
        // A0 (Slot) = 1, A1 (EP0) = 1
        self.add_flags = 0b11;
        self.drop_flags = 0;
    }
}

impl InputContext {
    /// 新しい入力コンテキストを作成
    pub fn new() -> Self {
        Self {
            input_control: InputControlContext::default(),
            slot: SlotContext::default(),
            endpoints: [EndpointContext::default(); 31],
        }
    }

    /// Address Device コマンド用の入力コンテキストを作成
    ///
    /// # Arguments
    /// * `speed` - デバイスの速度
    /// * `route_string` - ルートストリング（直接接続の場合は0）
    /// * `root_port` - ルートハブポート番号 (1-indexed)
    /// * `max_packet_size` - EP0の最大パケットサイズ
    /// * `tr_dequeue_ptr` - EP0転送リングのデキューポインタ
    pub fn for_address_device(
        speed: UsbSpeed,
        route_string: u32,
        root_port: u8,
        max_packet_size: u16,
        tr_dequeue_ptr: u64,
    ) -> Self {
        let mut ctx = Self::new();

        // Input Control Context: Add Slot (A0) and EP0 (A1)
        ctx.input_control.set_for_address_device();

        // Slot Context
        // Context Entries = 1 (only EP0 is valid initially)
        ctx.slot.set_context(speed, route_string, root_port, 1);

        // Endpoint 0 Context (Control Bidirectional)
        // EP Type = 4 (Control Bidirectional)
        // CErr = 3 (maximum error count)
        ctx.endpoints[0].set_context(
            4, // Control Bidirectional
            max_packet_size,
            0, // Max Burst Size = 0 for control
            tr_dequeue_ptr,
            0, // Interval = 0 for control
            3, // Error Count = 3
        );

        ctx
    }

    /// Configure Endpoint コマンド用の入力コンテキストを作成
    ///
    /// # Arguments
    /// * `slot` - 既存のスロットコンテキスト
    /// * `endpoints` - 設定するエンドポイントのリスト (DCI, Context)
    pub fn for_configure_endpoint(slot: &SlotContext, endpoints: &[(u8, EndpointContext)]) -> Self {
        let mut ctx = Self::new();

        // 最大のDCIを検出してContext Entriesを設定
        let max_dci = endpoints.iter().map(|(dci, _)| *dci).max().unwrap_or(1);

        // Slot Contextをコピーして更新
        ctx.slot = *slot;
        ctx.slot.route_string_and_speed =
            (ctx.slot.route_string_and_speed & 0x07FFFFFF) | ((max_dci as u32) << 27);

        // Add flags: A0 (Slot) と各エンドポイント
        let mut add_flags = 1u32; // A0 = 1
        for (dci, ep_ctx) in endpoints {
            let idx = (*dci as usize).saturating_sub(1);
            if idx < 31 {
                ctx.endpoints[idx] = *ep_ctx;
                add_flags |= 1 << *dci;
            }
        }
        ctx.input_control.add_flags = add_flags;

        ctx
    }

    /// 物理アドレスを取得
    pub fn physical_address(&self) -> u64 {
        self as *const Self as u64
    }
}

impl Default for InputContext {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for DeviceContext {
    fn default() -> Self {
        Self {
            slot: SlotContext::default(),
            endpoints: [EndpointContext::default(); 31],
        }
    }
}
