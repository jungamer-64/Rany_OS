// ============================================================================
// src/io/usb/class/hub/mod.rs - USB Hub Class Driver Module
// ============================================================================
//!
//! # USB Hub クラスドライバ
//!
//! USBハブの制御とデバイスの再帰的列挙をサポート。
//!
//! ## 機能
//! - ハブポートの電源管理
//! - デバイス接続/切断検出
//! - ポートリセットとデバイス列挙
//! - 多段ハブ対応（再帰的列挙）
//!
//! ## 参照仕様
//! - USB 2.0 Specification (Chapter 11)
//! - USB 3.2 Specification (Hub Class)

mod types;
mod device;
mod events;
mod tree;

// Re-export types
pub use types::{
    HUB_CLASS, HUB_SUBCLASS,
    HUB_PROTOCOL_FS, HUB_PROTOCOL_HS_SINGLE_TT, HUB_PROTOCOL_HS_MULTI_TT, HUB_PROTOCOL_SS,
    HUB_GET_STATUS, HUB_CLEAR_FEATURE, HUB_SET_FEATURE, HUB_GET_DESCRIPTOR,
    HUB_SET_DESCRIPTOR, HUB_CLEAR_TT_BUFFER, HUB_RESET_TT, HUB_GET_TT_STATE,
    HUB_STOP_TT, HUB_SET_HUB_DEPTH, HUB_GET_PORT_ERR_COUNT,
    HUB_C_HUB_LOCAL_POWER, HUB_C_HUB_OVER_CURRENT,
    PORT_CONNECTION, PORT_ENABLE, PORT_SUSPEND, PORT_OVER_CURRENT, PORT_RESET,
    PORT_LINK_STATE, PORT_POWER, PORT_LOW_SPEED, PORT_HIGH_SPEED, PORT_TEST,
    PORT_INDICATOR, PORT_REMOTE_WAKE_MASK, BH_PORT_RESET, FORCE_LINKPM_ACCEPT,
    C_PORT_CONNECTION, C_PORT_ENABLE, C_PORT_SUSPEND, C_PORT_OVER_CURRENT,
    C_PORT_RESET, C_BH_PORT_RESET, C_PORT_LINK_STATE, C_PORT_CONFIG_ERROR,
    HUB_DESCRIPTOR_TYPE_20, HUB_DESCRIPTOR_TYPE_30,
    HubSpeed, HubDescriptor, HubCharacteristics, DeviceSpeed, HubPortStatus,
};

// Re-export device
pub use device::{HubDevice, AttachedDevice};

// Re-export events
pub use events::{HubEvent, HubEnumerationState, HubEnumerator};

// Re-export tree
pub use tree::{
    MAX_HUB_DEPTH,
    HubTreeNode, ChildDevice, RecursiveHubEnumerator,
    EnumerationTask, EnumeratedDevice, HubEnumerationError,
    hub_enumerator,
};
