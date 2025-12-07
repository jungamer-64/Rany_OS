// ============================================================================
// src/io/usb/class/hub/tree.rs - Recursive Hub Enumeration Tree
// ============================================================================
//!
//! # 再帰的ハブ列挙ツリー

#![allow(dead_code)]

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use spin::Mutex;

use super::types::DeviceSpeed;

// ============================================================================
// Constants
// ============================================================================

/// 最大ハブ深度 (USB 仕様: 7段まで)
pub const MAX_HUB_DEPTH: u8 = 7;

// ============================================================================
// Hub Tree Node
// ============================================================================

/// ハブツリーノード
#[derive(Debug, Clone)]
pub struct HubTreeNode {
    /// スロットID
    pub slot_id: u8,
    /// ハブ深度
    pub depth: u8,
    /// 親ハブのスロットID (ルートハブは0)
    pub parent_slot: u8,
    /// 親ハブのポート番号
    pub parent_port: u8,
    /// ポート数
    pub num_ports: u8,
    /// 子デバイス情報
    pub children: Vec<Option<ChildDevice>>,
}

/// 子デバイス情報
#[derive(Debug, Clone)]
pub struct ChildDevice {
    /// スロットID
    pub slot_id: u8,
    /// デバイス速度
    pub speed: DeviceSpeed,
    /// ハブかどうか
    pub is_hub: bool,
    /// ハブの場合、そのツリーノードインデックス
    pub hub_node_index: Option<usize>,
}

// ============================================================================
// Recursive Hub Enumerator
// ============================================================================

/// 再帰的ハブ列挙マネージャ
pub struct RecursiveHubEnumerator {
    /// ハブツリー
    hub_tree: Mutex<Vec<HubTreeNode>>,
    /// 列挙待ちキュー (hub_node_index, port)
    enumeration_queue: Mutex<VecDeque<(usize, u8)>>,
    /// 次のスロットID
    next_slot_id: AtomicU8,
    /// 列挙中フラグ
    enumerating: AtomicBool,
    /// 列挙完了数
    enumerated_count: AtomicU32,
    /// エラー数
    error_count: AtomicU32,
}

impl RecursiveHubEnumerator {
    /// 新しいエニュメレータを作成
    pub const fn new() -> Self {
        Self {
            hub_tree: Mutex::new(Vec::new()),
            enumeration_queue: Mutex::new(VecDeque::new()),
            next_slot_id: AtomicU8::new(1),
            enumerating: AtomicBool::new(false),
            enumerated_count: AtomicU32::new(0),
            error_count: AtomicU32::new(0),
        }
    }
    
    /// ルートハブを登録
    pub fn register_root_hub(&self, slot_id: u8, num_ports: u8) -> usize {
        let node = HubTreeNode {
            slot_id,
            depth: 0,
            parent_slot: 0,
            parent_port: 0,
            num_ports,
            children: vec![None; num_ports as usize],
        };
        
        let mut tree = self.hub_tree.lock();
        let index = tree.len();
        tree.push(node);
        
        // 全ポートを列挙キューに追加
        let mut queue = self.enumeration_queue.lock();
        for port in 1..=num_ports {
            queue.push_back((index, port));
        }
        
        index
    }
    
    /// 子ハブを登録
    pub fn register_child_hub(
        &self,
        parent_index: usize,
        parent_port: u8,
        slot_id: u8,
        num_ports: u8,
    ) -> Result<usize, HubEnumerationError> {
        let mut tree = self.hub_tree.lock();
        
        // 親ノードの検証
        let parent = tree.get(parent_index)
            .ok_or(HubEnumerationError::InvalidParent)?;
        
        // 深度チェック
        let new_depth = parent.depth + 1;
        if new_depth >= MAX_HUB_DEPTH {
            return Err(HubEnumerationError::MaxDepthExceeded);
        }
        
        let parent_slot = parent.slot_id;
        
        // 新しいノードを作成
        let node = HubTreeNode {
            slot_id,
            depth: new_depth,
            parent_slot,
            parent_port,
            num_ports,
            children: vec![None; num_ports as usize],
        };
        
        let index = tree.len();
        tree.push(node);
        
        // 親の子リストを更新
        if let Some(parent_node) = tree.get_mut(parent_index) {
            if (parent_port as usize) <= parent_node.children.len() {
                parent_node.children[(parent_port - 1) as usize] = Some(ChildDevice {
                    slot_id,
                    speed: DeviceSpeed::High, // 後で更新
                    is_hub: true,
                    hub_node_index: Some(index),
                });
            }
        }
        
        // 子ハブのポートを列挙キューに追加
        drop(tree); // ロック解放
        let mut queue = self.enumeration_queue.lock();
        for port in 1..=num_ports {
            queue.push_back((index, port));
        }
        
        Ok(index)
    }
    
    /// 非ハブデバイスを登録
    pub fn register_device(
        &self,
        parent_index: usize,
        parent_port: u8,
        slot_id: u8,
        speed: DeviceSpeed,
    ) -> Result<(), HubEnumerationError> {
        let mut tree = self.hub_tree.lock();
        
        if let Some(parent_node) = tree.get_mut(parent_index) {
            if (parent_port as usize) <= parent_node.children.len() {
                parent_node.children[(parent_port - 1) as usize] = Some(ChildDevice {
                    slot_id,
                    speed,
                    is_hub: false,
                    hub_node_index: None,
                });
                self.enumerated_count.fetch_add(1, Ordering::SeqCst);
                return Ok(());
            }
        }
        
        Err(HubEnumerationError::InvalidParent)
    }
    
    /// 次の列挙タスクを取得
    pub fn next_enumeration_task(&self) -> Option<EnumerationTask> {
        self.enumeration_queue.lock().pop_front().map(|(hub_index, port)| {
            EnumerationTask { hub_index, port }
        })
    }
    
    /// 列挙開始
    pub fn start_enumeration(&self) {
        self.enumerating.store(true, Ordering::SeqCst);
    }
    
    /// 列挙停止
    pub fn stop_enumeration(&self) {
        self.enumerating.store(false, Ordering::SeqCst);
    }
    
    /// 列挙中かどうか
    pub fn is_enumerating(&self) -> bool {
        self.enumerating.load(Ordering::Acquire)
    }
    
    /// 列挙が完了したか（キューが空）
    pub fn is_complete(&self) -> bool {
        self.enumeration_queue.lock().is_empty()
    }
    
    /// 次のスロットIDを割り当て
    pub fn allocate_slot_id(&self) -> u8 {
        self.next_slot_id.fetch_add(1, Ordering::SeqCst)
    }
    
    /// ハブツリーを取得
    pub fn get_hub_tree(&self) -> Vec<HubTreeNode> {
        self.hub_tree.lock().clone()
    }
    
    /// ハブノードを取得
    pub fn get_hub_node(&self, index: usize) -> Option<HubTreeNode> {
        self.hub_tree.lock().get(index).cloned()
    }
    
    /// 統計を取得
    pub fn stats(&self) -> (u32, u32) {
        (
            self.enumerated_count.load(Ordering::Acquire),
            self.error_count.load(Ordering::Acquire),
        )
    }
    
    /// エラーを記録
    pub fn record_error(&self) {
        self.error_count.fetch_add(1, Ordering::SeqCst);
    }
    
    /// 全デバイスを列挙して返す
    pub fn all_devices(&self) -> Vec<EnumeratedDevice> {
        let tree = self.hub_tree.lock();
        let mut devices = Vec::new();
        
        for (hub_idx, hub) in tree.iter().enumerate() {
            for (port_idx, child) in hub.children.iter().enumerate() {
                if let Some(child) = child {
                    devices.push(EnumeratedDevice {
                        slot_id: child.slot_id,
                        speed: child.speed,
                        is_hub: child.is_hub,
                        hub_index: hub_idx,
                        port: (port_idx + 1) as u8,
                        depth: hub.depth + 1,
                    });
                }
            }
        }
        
        devices
    }
}

// ============================================================================
// Enumeration Types
// ============================================================================

/// 列挙タスク
#[derive(Debug, Clone, Copy)]
pub struct EnumerationTask {
    /// ハブノードインデックス
    pub hub_index: usize,
    /// ポート番号
    pub port: u8,
}

/// 列挙済みデバイス
#[derive(Debug, Clone)]
pub struct EnumeratedDevice {
    /// スロットID
    pub slot_id: u8,
    /// デバイス速度
    pub speed: DeviceSpeed,
    /// ハブかどうか
    pub is_hub: bool,
    /// 親ハブのインデックス
    pub hub_index: usize,
    /// ポート番号
    pub port: u8,
    /// ツリー深度
    pub depth: u8,
}

/// ハブ列挙エラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubEnumerationError {
    /// 無効な親ハブ
    InvalidParent,
    /// 最大深度超過
    MaxDepthExceeded,
    /// ポートエラー
    PortError,
    /// デバイス応答なし
    NoResponse,
    /// 設定失敗
    ConfigurationFailed,
}

// ============================================================================
// Global Enumerator
// ============================================================================

// グローバルエニュメレータ
static GLOBAL_HUB_ENUMERATOR: RecursiveHubEnumerator = RecursiveHubEnumerator::new();

/// グローバルハブエニュメレータを取得
pub fn hub_enumerator() -> &'static RecursiveHubEnumerator {
    &GLOBAL_HUB_ENUMERATOR
}
