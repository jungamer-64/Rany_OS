// ============================================================================
// src/io/usb/xhci/command.rs - xHCI Command Handling
// ============================================================================
//!
//! xHCI コマンド発行と完了待ち。
//!
//! ## コマンドタイプ
//! - Enable Slot
//! - Disable Slot
//! - Address Device
//! - Configure Endpoint
//! - Evaluate Context
//! - Reset Endpoint
//! - Stop Endpoint
//! - Set TR Dequeue Pointer
//! - Reset Device
//! - その他

#![allow(dead_code)]

use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};
use spin::Mutex;

use super::event_handler::CommandCompletionEvent;
use super::trb::{CompletionCode, Trb, TrbRing};
use crate::io::usb::{SlotId, UsbError, UsbResult};

// ============================================================================
// Command Builder
// ============================================================================

/// コマンドビルダー
pub struct CommandBuilder;

impl CommandBuilder {
    /// Enable Slot コマンド
    pub fn enable_slot(cycle: bool) -> Trb {
        Trb {
            parameter: 0,
            status: 0,
            control: (TrbTypeCmd::EnableSlot as u32) << 10 | if cycle { 1 } else { 0 },
        }
    }

    /// Disable Slot コマンド
    pub fn disable_slot(slot_id: SlotId, cycle: bool) -> Trb {
        Trb {
            parameter: 0,
            status: 0,
            control: (TrbTypeCmd::DisableSlot as u32) << 10
                | ((slot_id.0 as u32) << 24)
                | if cycle { 1 } else { 0 },
        }
    }

    /// Address Device コマンド
    pub fn address_device(
        input_context_ptr: u64,
        slot_id: SlotId,
        block_set_address: bool,
        cycle: bool,
    ) -> Trb {
        Trb {
            parameter: input_context_ptr,
            status: 0,
            control: (TrbTypeCmd::AddressDevice as u32) << 10
                | ((slot_id.0 as u32) << 24)
                | if block_set_address { 1 << 9 } else { 0 }
                | if cycle { 1 } else { 0 },
        }
    }

    /// Configure Endpoint コマンド
    pub fn configure_endpoint(
        input_context_ptr: u64,
        slot_id: SlotId,
        deconfigure: bool,
        cycle: bool,
    ) -> Trb {
        Trb {
            parameter: input_context_ptr,
            status: 0,
            control: (TrbTypeCmd::ConfigureEndpoint as u32) << 10
                | ((slot_id.0 as u32) << 24)
                | if deconfigure { 1 << 9 } else { 0 }
                | if cycle { 1 } else { 0 },
        }
    }

    /// Evaluate Context コマンド
    pub fn evaluate_context(input_context_ptr: u64, slot_id: SlotId, cycle: bool) -> Trb {
        Trb {
            parameter: input_context_ptr,
            status: 0,
            control: (TrbTypeCmd::EvaluateContext as u32) << 10
                | ((slot_id.0 as u32) << 24)
                | if cycle { 1 } else { 0 },
        }
    }

    /// Reset Endpoint コマンド
    pub fn reset_endpoint(slot_id: SlotId, endpoint_id: u8, preserve_tsp: bool, cycle: bool) -> Trb {
        Trb {
            parameter: 0,
            status: 0,
            control: (TrbTypeCmd::ResetEndpoint as u32) << 10
                | ((slot_id.0 as u32) << 24)
                | ((endpoint_id as u32) << 16)
                | if preserve_tsp { 1 << 9 } else { 0 }
                | if cycle { 1 } else { 0 },
        }
    }

    /// Stop Endpoint コマンド
    pub fn stop_endpoint(slot_id: SlotId, endpoint_id: u8, suspend: bool, cycle: bool) -> Trb {
        Trb {
            parameter: 0,
            status: 0,
            control: (TrbTypeCmd::StopEndpoint as u32) << 10
                | ((slot_id.0 as u32) << 24)
                | ((endpoint_id as u32) << 16)
                | if suspend { 1 << 23 } else { 0 }
                | if cycle { 1 } else { 0 },
        }
    }

    /// Set TR Dequeue Pointer コマンド
    pub fn set_tr_dequeue_pointer(
        dequeue_ptr: u64,
        slot_id: SlotId,
        endpoint_id: u8,
        stream_id: u16,
        cycle: bool,
    ) -> Trb {
        Trb {
            parameter: (dequeue_ptr & !0xF) | if cycle { 1 } else { 0 },
            status: (stream_id as u32) << 16,
            control: (TrbTypeCmd::SetTrDequeuePointer as u32) << 10
                | ((slot_id.0 as u32) << 24)
                | ((endpoint_id as u32) << 16),
        }
    }

    /// Reset Device コマンド
    pub fn reset_device(slot_id: SlotId, cycle: bool) -> Trb {
        Trb {
            parameter: 0,
            status: 0,
            control: (TrbTypeCmd::ResetDevice as u32) << 10
                | ((slot_id.0 as u32) << 24)
                | if cycle { 1 } else { 0 },
        }
    }

    /// No Op コマンド
    pub fn noop(cycle: bool) -> Trb {
        Trb {
            parameter: 0,
            status: 0,
            control: (TrbTypeCmd::NoOp as u32) << 10 | if cycle { 1 } else { 0 },
        }
    }
}

/// コマンドTRBタイプ
#[repr(u32)]
enum TrbTypeCmd {
    NoOp = 23,
    EnableSlot = 9,
    DisableSlot = 10,
    AddressDevice = 11,
    ConfigureEndpoint = 12,
    EvaluateContext = 13,
    ResetEndpoint = 14,
    StopEndpoint = 15,
    SetTrDequeuePointer = 16,
    ResetDevice = 17,
    ForceEvent = 18,
    NegotiateBandwidth = 19,
    SetLatencyTolerance = 20,
    GetPortBandwidth = 21,
    ForceHeader = 22,
    GetExtendedProperty = 24,
    SetExtendedProperty = 25,
}

// ============================================================================
// Command Executor
// ============================================================================

/// コマンドエグゼキュータ
pub struct CommandExecutor {
    /// 保留中のコマンド
    pending: Mutex<Vec<PendingCommand>>,
    /// 次のコマンドID
    next_id: AtomicU64,
}

struct PendingCommand {
    id: u64,
    trb_address: u64,
    completed: AtomicBool,
    result: Mutex<Option<CommandCompletionEvent>>,
    waker: Mutex<Option<Waker>>,
}

impl CommandExecutor {
    /// 新しいコマンドエグゼキュータを作成
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(1),
        }
    }

    /// コマンドを送信
    pub fn send_command<'a>(
        &'a self,
        ring: &mut TrbRing,
        trb: Trb,
        ring_doorbell: impl FnOnce(),
    ) -> UsbResult<CommandFuture<'a>> {
        let trb_address = ring.enqueue(trb).ok_or(UsbError::NoResources)?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);

        let pending = PendingCommand {
            id,
            trb_address,
            completed: AtomicBool::new(false),
            result: Mutex::new(None),
            waker: Mutex::new(None),
        };

        self.pending.lock().push(pending);

        // ドアベルを鳴らす
        ring_doorbell();

        Ok(CommandFuture {
            executor: self,
            id,
        })
    }

    /// コマンド完了を通知
    pub fn notify_completion(&self, event: CommandCompletionEvent) {
        let mut pending = self.pending.lock();
        for cmd in pending.iter() {
            if cmd.trb_address == event.trb_address {
                *cmd.result.lock() = Some(event);
                cmd.completed.store(true, Ordering::Release);
                if let Some(waker) = cmd.waker.lock().take() {
                    waker.wake();
                }
                break;
            }
        }
    }

    /// 完了したコマンドをクリーンアップ
    pub fn cleanup_completed(&self) {
        self.pending.lock().retain(|cmd| !cmd.completed.load(Ordering::Acquire));
    }
}

impl Default for CommandExecutor {
    fn default() -> Self {
        Self::new()
    }
}

/// コマンドFuture
pub struct CommandFuture<'a> {
    executor: &'a CommandExecutor,
    id: u64,
}

impl<'a> Future for CommandFuture<'a> {
    type Output = UsbResult<CommandCompletionEvent>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let pending = self.executor.pending.lock();
        
        if let Some(cmd) = pending.iter().find(|c| c.id == self.id) {
            if cmd.completed.load(Ordering::Acquire) {
                let result = cmd.result.lock().take();
                drop(pending);
                
                if let Some(event) = result {
                    if event.completion_code == CompletionCode::Success {
                        Poll::Ready(Ok(event))
                    } else {
                        Poll::Ready(Err(UsbError::XhciError(alloc::format!(
                            "Command failed: {:?}",
                            event.completion_code
                        ))))
                    }
                } else {
                    Poll::Ready(Err(UsbError::Other("No completion event".into())))
                }
            } else {
                *cmd.waker.lock() = Some(cx.waker().clone());
                Poll::Pending
            }
        } else {
            Poll::Ready(Err(UsbError::Other("Command not found".into())))
        }
    }
}

// ============================================================================
// High-level Command API
// ============================================================================

/// 高レベルコマンドAPI
pub struct CommandApi<'a> {
    executor: &'a CommandExecutor,
    command_ring: &'a Mutex<TrbRing>,
    ring_doorbell: fn(),
}

impl<'a> CommandApi<'a> {
    pub fn new(
        executor: &'a CommandExecutor,
        command_ring: &'a Mutex<TrbRing>,
        ring_doorbell: fn(),
    ) -> Self {
        Self {
            executor,
            command_ring,
            ring_doorbell,
        }
    }

    /// スロットを有効化
    pub async fn enable_slot(&self) -> UsbResult<SlotId> {
        let cycle = self.command_ring.lock().cycle_bit();
        let trb = CommandBuilder::enable_slot(cycle);
        let future = {
            let mut ring = self.command_ring.lock();
            self.executor.send_command(&mut ring, trb, self.ring_doorbell)?
        };
        let result = future.await?;
        Ok(result.slot_id)
    }

    /// スロットを無効化
    pub async fn disable_slot(&self, slot_id: SlotId) -> UsbResult<()> {
        let cycle = self.command_ring.lock().cycle_bit();
        let trb = CommandBuilder::disable_slot(slot_id, cycle);
        let future = {
            let mut ring = self.command_ring.lock();
            self.executor.send_command(&mut ring, trb, self.ring_doorbell)?
        };
        future.await?;
        Ok(())
    }

    /// デバイスにアドレスを割り当て
    pub async fn address_device(
        &self,
        input_context_ptr: u64,
        slot_id: SlotId,
        block_set_address: bool,
    ) -> UsbResult<()> {
        let cycle = self.command_ring.lock().cycle_bit();
        let trb = CommandBuilder::address_device(input_context_ptr, slot_id, block_set_address, cycle);
        let future = {
            let mut ring = self.command_ring.lock();
            self.executor.send_command(&mut ring, trb, self.ring_doorbell)?
        };
        future.await?;
        Ok(())
    }

    /// エンドポイントを設定
    pub async fn configure_endpoint(
        &self,
        input_context_ptr: u64,
        slot_id: SlotId,
        deconfigure: bool,
    ) -> UsbResult<()> {
        let cycle = self.command_ring.lock().cycle_bit();
        let trb = CommandBuilder::configure_endpoint(input_context_ptr, slot_id, deconfigure, cycle);
        let future = {
            let mut ring = self.command_ring.lock();
            self.executor.send_command(&mut ring, trb, self.ring_doorbell)?
        };
        future.await?;
        Ok(())
    }

    /// エンドポイントをリセット
    pub async fn reset_endpoint(&self, slot_id: SlotId, endpoint_id: u8) -> UsbResult<()> {
        let cycle = self.command_ring.lock().cycle_bit();
        let trb = CommandBuilder::reset_endpoint(slot_id, endpoint_id, false, cycle);
        let future = {
            let mut ring = self.command_ring.lock();
            self.executor.send_command(&mut ring, trb, self.ring_doorbell)?
        };
        future.await?;
        Ok(())
    }

    /// デバイスをリセット
    pub async fn reset_device(&self, slot_id: SlotId) -> UsbResult<()> {
        let cycle = self.command_ring.lock().cycle_bit();
        let trb = CommandBuilder::reset_device(slot_id, cycle);
        let future = {
            let mut ring = self.command_ring.lock();
            self.executor.send_command(&mut ring, trb, self.ring_doorbell)?
        };
        future.await?;
        Ok(())
    }
}
