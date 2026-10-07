// ============================================================================
// src/io/usb/xhci/controller.rs - xHCI Host Controller
// ============================================================================
//!
//! xHCI ホストコントローラの実装。
//!
//! ## 機能
//! - コントローラ初期化とリセット
//! - コマンドリング/イベントリング管理
//! - ポート状態管理
//! - デバイス列挙
use super::memory::SharedRegion;
use super::request::{Receipt, RequestFuture};
use super::ring::{EventRing, PreparedEventRing, PreparedProducerRing, ProducerRing};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use exorust_sync::Mutex;
use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::dma::{
    CpuDmaLease, DmaAllocationRequest, DmaCloseError, DmaDeviceAddress, DmaDirection,
    DmaQueueIdentity, InFlightDmaLease,
};

use super::context::InputContext;
use super::event_handler::{
    CommandCompletionEvent, EventHandler, PortStatusChangeEvent, ProcessedEvent, TransferEvent,
};
use super::trb::{CompletionCode, Trb};
use super::{
    COMMAND_RING_SIZE, EVENT_RING_SIZE, MAX_ENDPOINTS, MAX_SLOTS, PORTSC_CCS, PORTSC_CHANGE_MASK,
    PORTSC_CSC, PORTSC_OCA, PORTSC_PEC, PORTSC_PED, PORTSC_PP, PORTSC_PR, PORTSC_PRC,
    TRANSFER_RING_SIZE, USBCMD_HCRST, USBCMD_INTE, USBCMD_RUN, USBSTS_CNR, USBSTS_HCH,
};
use crate::{PortNumber, PortStatus, SetupPacket, SlotId, UsbError, UsbResult, UsbSpeed};
#[path = "controller/retirement.rs"]
mod retirement;
mod runtime_ops;
pub(crate) use retirement::ControllerRetirement;

// ============================================================================
// xHCI Controller
// ============================================================================

/// xHCIコントローラ
pub struct XhciController {
    /// DMA 割り当てに使う PCI locator
    pub(crate) pci_locator: PackedPciLocation,
    /// Operational Registers オフセット
    registers: super::registers::XhciRegisters,
    /// Event consumer owns the only dequeue write path.
    event_dequeue: Mutex<hal::mmio::OwnedMmioRegister<u64, hal::WriteOnly>>,
    /// 最大スロット数
    max_slots: u8,
    /// 最大ポート数
    max_ports: u8,
    /// コマンドリング
    command_ring: Mutex<ProducerRing>,
    /// イベントリング
    event_ring: Mutex<EventRing>,
    /// Shared descriptor owners remain retained until hardware stop is proven.
    erst: Mutex<SharedRegion>,
    dcbaa: Mutex<SharedRegion>,
    /// Scratchpad pages and their address array remain reachable through DCBAA0.
    scratchpads: Mutex<Vec<SharedRegion>>,
    context_stride: usize,
    device_contexts: Mutex<Vec<Option<SharedRegion>>>,
    pub(crate) transfer_rings: Mutex<Vec<Vec<Option<Box<EndpointQueue>>>>>,
    /// Input command RAM remains owned even after the waiting Future cancels.
    command_requests: Mutex<Vec<CommandRequest>>,
    failed_inputs: Mutex<Vec<SharedRegion>>,
    /// Failed unmap owners remain available to stop/reconciliation.
    retirement_failures: Mutex<Vec<DmaCloseError>>,
    /// 実行中フラグ
    running: AtomicBool,
}

struct CommandRequest {
    address: u64,
    input: Option<SharedRegion>,
    receipt: Arc<Receipt<CommandCompletionResult>>,
}

/// コマンド完了結果
pub(crate) struct CommandCompletionResult {
    pub completion_code: CompletionCode,
    pub slot_id: SlotId,
}

pub(super) enum TransferKind {
    Control(SetupPacket),
    Normal,
    Isochronous,
}

pub(crate) struct EndpointQueue {
    ring: ProducerRing,
    state: EndpointState,
}

enum EndpointState {
    Idle,
    Active(TransferRequest),
    Halted(TransferRequest),
}

struct TransferRequest {
    addresses: Vec<DmaDeviceAddress>,
    receipt: Arc<Receipt<TransferCompletionResult>>,
    memory: Option<InFlightDmaLease>,
    length: usize,
    residual: Option<u32>,
    control: bool,
}

pub(super) struct TransferCompletionResult {
    pub transferred: usize,
    pub memory: Option<CpuDmaLease>,
}

impl XhciController {
    /// 新しいxHCIコントローラを作成
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
    pub fn new(mapping: hal::MappedMmio, pci_locator: PackedPciLocation) -> UsbResult<Self> {
        let (registers, event_dequeue) = super::registers::XhciRegisters::new(mapping)?;
        let max_slots = registers.limits.slots;
        let max_ports = registers.limits.ports;
        if !registers.supports_4k_pages() {
            return Err(UsbError::InvalidController);
        }

        let command_identity = queue_identity(pci_locator, 0)?;
        let event_identity = queue_identity(pci_locator, 1)?;
        let command_ring = PreparedProducerRing::prepare(
            allocate_dma(pci_locator, COMMAND_RING_SIZE * 16, DmaDirection::ToDevice)?,
            command_identity,
            COMMAND_RING_SIZE as u16,
        )?
        .activate()?;
        let event_ring = PreparedEventRing::prepare(
            allocate_dma(pci_locator, EVENT_RING_SIZE * 16, DmaDirection::FromDevice)?,
            event_identity,
            EVENT_RING_SIZE as u16,
        )?
        .activate()?;
        let event_address = event_ring.device_address().get();
        let erst = SharedRegion::prepare(
            allocate_dma(pci_locator, 64, DmaDirection::ToDevice)?,
            event_identity,
            |bytes| {
                bytes.fill(0);
                bytes[..8].copy_from_slice(&event_address.to_le_bytes());
                bytes[8..12].copy_from_slice(&(EVENT_RING_SIZE as u32).to_le_bytes());
            },
        )?;
        let mut scratchpads = Vec::new();
        scratchpads
            .try_reserve_exact(usize::from(registers.limits.scratchpad_pages) + 1)
            .map_err(|_| UsbError::NoResources)?;
        for _ in 0..registers.limits.scratchpad_pages {
            let page = SharedRegion::prepare(
                allocate_dma(pci_locator, 4096, DmaDirection::Bidirectional)?,
                command_identity,
                |bytes| bytes.fill(0),
            )?;
            if !page.address.get().is_multiple_of(4096) {
                return Err(UsbError::InvalidController);
            }
            scratchpads.push(page);
        }
        let scratchpad_array = if scratchpads.is_empty() {
            0
        } else {
            let array = SharedRegion::prepare(
                allocate_dma(pci_locator, scratchpads.len() * 8, DmaDirection::ToDevice)?,
                command_identity,
                |bytes| {
                    bytes.fill(0);
                    for (index, page) in scratchpads.iter().enumerate() {
                        bytes[index * 8..index * 8 + 8]
                            .copy_from_slice(&page.address.get().to_le_bytes());
                    }
                },
            )?;
            let address = array.address.get();
            scratchpads.push(array);
            address
        };
        let dcbaa = SharedRegion::prepare(
            allocate_dma(
                pci_locator,
                (usize::from(max_slots) + 1) * 8,
                DmaDirection::Bidirectional,
            )?,
            command_identity,
            |bytes| {
                bytes.fill(0);
                bytes[..8].copy_from_slice(&scratchpad_array.to_le_bytes());
            },
        )?;
        let context_stride = registers.limits.context_stride;

        // Device contextsの初期化
        let device_contexts: Vec<Option<SharedRegion>> = (0..MAX_SLOTS).map(|_| None).collect();
        // Transfer ringsの初期化
        let transfer_rings: Vec<Vec<Option<Box<EndpointQueue>>>> = (0..MAX_SLOTS)
            .map(|_| (0..MAX_ENDPOINTS).map(|_| None).collect())
            .collect();

        let controller = Self {
            pci_locator,
            registers,
            event_dequeue: Mutex::new(event_dequeue),
            max_slots,
            max_ports,
            command_ring: Mutex::new(command_ring),
            event_ring: Mutex::new(event_ring),
            erst: Mutex::new(erst),
            dcbaa: Mutex::new(dcbaa),
            scratchpads: Mutex::new(scratchpads),
            context_stride,
            command_requests: Mutex::new(Vec::with_capacity(COMMAND_RING_SIZE - 1)),
            failed_inputs: Mutex::new(Vec::new()),
            device_contexts: Mutex::new(device_contexts),
            transfer_rings: Mutex::new(transfer_rings),
            retirement_failures: Mutex::new(Vec::new()),
            running: AtomicBool::new(false),
        };

        Ok(controller)
    }

    /// コントローラを初期化
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
    pub fn init(&mut self) -> UsbResult<()> {
        // コントローラを停止
        self.stop()?;

        // コントローラをリセット
        self.reset()?;

        // 最大スロット数を設定
        self.registers.configure_slots();

        // DCBAAを設定 (デバイス可視アドレスで)
        self.registers.set_contexts(self.dcbaa.lock().address.get());

        // コマンドリングを設定
        let cmd_ring = self.command_ring.lock();
        let crcr_val = cmd_ring.device_address().get() | 1; // RCS = 1
        drop(cmd_ring);
        self.registers.set_command_ring(crcr_val);

        // イベントリングを設定
        let event_ring = self.event_ring.lock();

        // ERSTSZ

        // ERDP
        self.event_dequeue
            .lock()
            .write(event_ring.device_address().get());

        // ERSTBA (デバイス可視アドレスで)
        self.registers
            .set_event_table(self.erst.lock().address.get());
        drop(event_ring);

        // 割り込みを有効化
        self.registers.enable_interrupt();

        // コントローラを開始
        self.start()?;

        Ok(())
    }

    /// コントローラを停止
    pub(crate) fn stop(&self) -> UsbResult<()> {
        self.registers.update_command(USBCMD_RUN, 0);

        // HCHビットが1になるまで待機
        for _ in 0..100 {
            let status = self.registers.status();
            if (status & USBSTS_HCH) != 0 {
                self.running.store(false, Ordering::Release);
                return Ok(());
            }
        }

        Err(UsbError::Timeout)
    }

    /// コントローラをリセット
    fn reset(&self) -> UsbResult<()> {
        self.registers.update_command(0, USBCMD_HCRST);

        // HCRSTビットが0になるまで待機
        for _ in 0..100 {
            let cmd = self.registers.command();
            if (cmd & USBCMD_HCRST) == 0 {
                // CNRビットも確認
                let status = self.registers.status();
                if (status & USBSTS_CNR) == 0 {
                    return Ok(());
                }
            }
        }

        Err(UsbError::Timeout)
    }

    /// コントローラを開始
    fn start(&self) -> UsbResult<()> {
        self.registers.update_command(0, USBCMD_RUN | USBCMD_INTE);

        // HCHビットが0になるまで待機
        for _ in 0..100 {
            let status = self.registers.status();
            if (status & USBSTS_HCH) == 0 {
                self.running.store(true, Ordering::SeqCst);
                return Ok(());
            }
        }

        Err(UsbError::Timeout)
    }

    /// ポート状態を取得
    ///
    /// # Errors
    /// An invalid port or an unavailable register mapping leaves hardware unchanged.
    pub fn port_status(&self, port: PortNumber) -> UsbResult<PortStatus> {
        let portsc = self.registers.port_status(port)?;

        let speed = match (portsc >> 10) & 0x0F {
            1 => Some(UsbSpeed::Full),
            2 => Some(UsbSpeed::Low),
            3 => Some(UsbSpeed::High),
            4 => Some(UsbSpeed::Super),
            5 => Some(UsbSpeed::SuperPlus),
            _ => None,
        };

        Ok(PortStatus {
            connected: (portsc & PORTSC_CCS) != 0,
            enabled: (portsc & PORTSC_PED) != 0,
            suspended: false,
            overcurrent: (portsc & PORTSC_OCA) != 0,
            reset: (portsc & PORTSC_PR) != 0,
            powered: (portsc & PORTSC_PP) != 0,
            connect_change: (portsc & PORTSC_CSC) != 0,
            enable_change: (portsc & PORTSC_PEC) != 0,
            reset_change: (portsc & PORTSC_PRC) != 0,
            speed,
        })
    }

    /// ポートをリセット
    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the device operation fails.
    pub async fn reset_port(&self, port: PortNumber) -> UsbResult<UsbSpeed> {
        // リセットを開始
        self.registers
            .update_port(port, PORTSC_CHANGE_MASK, PORTSC_PR)?;

        // リセット完了を待機
        for _ in 0..100 {
            let portsc = self.registers.port_status(port)?;
            if (portsc & PORTSC_PRC) != 0 {
                // リセット完了、変更フラグをクリア
                self.registers
                    .update_port(port, PORTSC_CHANGE_MASK, PORTSC_PRC)?;

                let speed_code = ((portsc >> 10) & 0x0F) as u8;
                return UsbSpeed::from_code(speed_code)
                    .ok_or(UsbError::Other("Unknown speed".into()));
            }
        }

        Err(UsbError::Timeout)
    }

    /// ポートをサスペンド
    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the device operation fails.
    pub async fn suspend_port(&self, port: PortNumber) -> UsbResult<()> {
        let portsc = self.registers.port_status(port)?;

        if (portsc & PORTSC_PED) == 0 {
            return Err(UsbError::Other("Port disabled".into()));
        }

        // U3 (Suspend) = 3
        let pls_u3 = 3;
        self.registers.update_port(
            port,
            PORTSC_CHANGE_MASK | (0xF << 5),
            (pls_u3 << 5) | (1 << 16),
        )?;

        // 状態遷移待ち（必要に応じて）
        Ok(())
    }

    /// ポートをレジューム
    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the device operation fails.
    pub async fn resume_port(&self, port: PortNumber) -> UsbResult<()> {
        let portsc = self.registers.port_status(port)?;

        // USB 2.0 vs 3.0 check
        // Speed is in bits 10-13.
        // 1=Full, 2=Low, 3=High (USB2)
        // 4=Super, 5=SuperPlus (USB3)
        let speed_val = (portsc >> 10) & 0xF;
        let is_usb3 = speed_val >= 4;

        let pls_resume = if is_usb3 {
            0 // U0
        } else {
            15 // Resume
        };

        self.registers.update_port(
            port,
            PORTSC_CHANGE_MASK | (0xF << 5),
            (pls_resume << 5) | (1 << 16),
        )?;

        Ok(())
    }

    /// デバイスをサスペンド
    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the device operation fails.
    pub async fn suspend_device(&self, slot_id: SlotId) -> UsbResult<()> {
        let port = self.get_root_port_for_slot(slot_id).await?;
        self.suspend_port(port).await
    }

    /// デバイスをレジューム
    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the device operation fails.
    pub async fn resume_device(&self, slot_id: SlotId) -> UsbResult<()> {
        let port = self.get_root_port_for_slot(slot_id).await?;
        self.resume_port(port).await
    }

    /// スロットIDからルートハブポート番号を取得
    async fn get_root_port_for_slot(&self, slot_id: SlotId) -> UsbResult<PortNumber> {
        let mut device_contexts = self.device_contexts.lock();
        if let Some(ctx) = device_contexts
            .get_mut(slot_id.as_usize())
            .and_then(|opt| opt.as_mut())
        {
            // latency_and_ports: Bits 16-23 is Root Hub Port Number
            let root_port_num = ((ctx.slot_context()?.latency_and_ports >> 16) & 0xFF) as u8;
            drop(device_contexts);

            if root_port_num == 0 {
                return Err(UsbError::InvalidDevice);
            }
            Ok(PortNumber(root_port_num - 1))
        } else {
            Err(UsbError::InvalidDevice)
        }
    }

    /// スロットを有効化
    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or rejected by the device.
    pub async fn enable_slot(&self) -> UsbResult<SlotId> {
        let trb = Trb::enable_slot(self.command_ring.lock().cycle_bit());
        let completion = self.submit_command(trb, None)?.await?;

        if completion.completion_code == CompletionCode::Success {
            Ok(completion.slot_id)
        } else {
            Err(UsbError::XhciError(alloc::format!(
                "Enable slot failed: {:?}",
                completion.completion_code
            )))
        }
    }

    fn submit_command(
        &self,
        trb: Trb,
        input: Option<SharedRegion>,
    ) -> UsbResult<RequestFuture<'_, CommandCompletionResult>> {
        let receipt = Receipt::new();
        let mut requests = self.command_requests.lock();
        if requests.len() >= COMMAND_RING_SIZE - 1 {
            return Err(UsbError::NoResources);
        }
        let address = self.command_ring.lock().enqueue(trb)?.get();
        requests.push(CommandRequest {
            address,
            input,
            receipt: Arc::clone(&receipt),
        });
        drop(requests);
        self.ring_doorbell(0, 0)?;
        Ok(RequestFuture::new(self, receipt))
    }

    /// Consumes a bounded batch in task context. Completion transitions occur
    /// in ring order while the event consumer is held; wakers run after both
    /// ring and dequeue locks have been released, allowing callback reentry.
    ///
    /// # Errors
    /// Register access or completion validation failure retains outstanding
    /// requests. Wakes from the already consumed event prefix are delivered.
    pub fn process_events(&self) -> UsbResult<()> {
        let mut wakes: [Option<CompletionWake>; EVENT_RING_SIZE] = core::array::from_fn(|_| None);
        let outcome = (|| {
            let mut ring = self.event_ring.lock();
            let mut dequeue = self.event_dequeue.lock();
            for wake in &mut wakes {
                let Some(trb) = ring.consume(&mut dequeue)? else {
                    break;
                };
                *wake = match EventHandler::parse_event(&trb) {
                    ProcessedEvent::CommandCompletion(event) => self
                        .handle_command_completion(&event)?
                        .map(CompletionWake::Command),
                    ProcessedEvent::Transfer(event) => self
                        .handle_transfer_completion(&event)
                        .map(CompletionWake::Transfer),
                    ProcessedEvent::PortStatusChange(event) => {
                        self.handle_port_status_change(&event);
                        None
                    }
                    _ => None,
                };
            }
            Ok(())
        })();
        for wake in wakes.into_iter().flatten() {
            wake.notify();
        }
        outcome
    }

    fn send_input_command(
        &self,
        input: &InputContext,
        build: impl FnOnce(u64) -> Trb,
    ) -> UsbResult<RequestFuture<'_, CommandCompletionResult>> {
        let queue = self.command_ring.lock().identity();
        let memory = SharedRegion::prepare(
            allocate_dma(
                self.pci_locator,
                33 * self.context_stride,
                DmaDirection::ToDevice,
            )?,
            queue,
            |bytes| super::memory::encode_input(input, self.context_stride, bytes),
        )?;
        let trb = build(memory.address.get());
        self.submit_command(trb, Some(memory))
    }

    /// コマンド完了イベントを処理
    fn handle_command_completion(
        &self,
        event: &CommandCompletionEvent,
    ) -> UsbResult<Option<Arc<Receipt<CommandCompletionResult>>>> {
        if event.completion_code == CompletionCode::Invalid {
            return Err(UsbError::InvalidController);
        }
        let request = {
            let mut requests = self.command_requests.lock();
            let index = requests
                .iter()
                .position(|request| request.address == event.trb_address)
                .ok_or(UsbError::InvalidController)?;
            self.command_ring
                .lock()
                .complete_through(DmaDeviceAddress::from_abi(event.trb_address))?;
            requests.remove(index)
        };
        let result = (|| {
            if let Some(input) = request.input {
                let queue = self.command_ring.lock().identity();
                match super::completion::finish_command_input(input.memory, queue) {
                    Ok(memory) => {
                        if let Err(error) = memory.close() {
                            let cause = error.cause();
                            self.retirement_failures.lock().push(error);
                            return Err(UsbError::Dma(cause));
                        }
                    }
                    Err(error) => {
                        let (cause, memory) = error.into_parts();
                        self.failed_inputs.lock().push(SharedRegion {
                            memory,
                            address: input.address,
                            identity: input.identity,
                        });
                        return Err(UsbError::Dma(cause));
                    }
                }
            }
            Ok(CommandCompletionResult {
                completion_code: event.completion_code,
                slot_id: event.slot_id,
            })
        })();
        request.receipt.complete(result);
        Ok(Some(request.receipt))
    }

    /// Completion may refer to an intermediate data TRB for a short control
    /// transfer. Such an event records the residual but keeps the input lease
    /// active until the final status TRB completes.
    fn handle_transfer_completion(
        &self,
        event: &TransferEvent,
    ) -> Option<Arc<Receipt<TransferCompletionResult>>> {
        let mut endpoints = self.transfer_rings.lock();
        let endpoint = endpoints
            .get_mut(event.slot_id.as_usize())?
            .get_mut(usize::from(event.endpoint_id))?
            .as_mut()?;
        let EndpointState::Active(request) = &mut endpoint.state else {
            return None;
        };
        if event.event_data || event.transfer_length as usize > request.length {
            return None;
        }
        let address = DmaDeviceAddress::from_abi(event.trb_pointer);
        if !request.addresses.contains(&address) {
            return None;
        }
        let final_event = request.addresses.last().copied() == Some(address);
        if !final_event && request.control && event.completion_code == CompletionCode::ShortPacket {
            request.residual = Some(event.transfer_length);
            return None;
        }
        if !final_event
            || !matches!(
                event.completion_code,
                CompletionCode::Success | CompletionCode::ShortPacket
            )
        {
            let EndpointState::Active(request) =
                core::mem::replace(&mut endpoint.state, EndpointState::Idle)
            else {
                unreachable!()
            };
            let receipt = Arc::clone(&request.receipt);
            let error = if event.completion_code == CompletionCode::StallError {
                UsbError::Stalled
            } else {
                UsbError::TransferError(crate::TransferStatus::Error(event.completion_code as u8))
            };
            request.receipt.complete(Err(error));
            endpoint.state = EndpointState::Halted(request);
            return Some(receipt);
        }
        if endpoint.ring.complete_through(address).is_err() {
            return None;
        }
        let EndpointState::Active(request) =
            core::mem::replace(&mut endpoint.state, EndpointState::Idle)
        else {
            unreachable!()
        };
        let result = (|| {
            let residual = request.residual.unwrap_or(event.transfer_length) as usize;
            let memory = if let Some(memory) = request.memory {
                let completed =
                    super::completion::finish_transfer(memory, endpoint.ring.identity())
                        .map_err(|error| UsbError::ActiveTransfer(Box::new(error)))?;
                Some(
                    completed
                        .return_to_cpu()
                        .map_err(|error| UsbError::CompletedTransfer(Box::new(error)))?,
                )
            } else {
                None
            };
            Ok(TransferCompletionResult {
                transferred: request.length - residual,
                memory,
            })
        })();
        request.receipt.complete(result);
        Some(request.receipt)
    }

    pub(super) fn submit_transfer(
        &self,
        slot: SlotId,
        dci: u8,
        kind: TransferKind,
        length: usize,
        direction_in: bool,
        source: Option<&[u8]>,
    ) -> UsbResult<RequestFuture<'_, TransferCompletionResult>> {
        if !slot.is_valid()
            || dci == 0
            || dci > 31
            || length > (TRANSFER_RING_SIZE - 4) * 65536
            || source.is_some_and(|bytes| bytes.len() != length)
        {
            return Err(UsbError::InvalidParameter);
        }
        let receipt = Receipt::new();
        let mut endpoints = self.transfer_rings.lock();
        let endpoint = endpoints
            .get_mut(slot.as_usize())
            .and_then(|entries| entries.get_mut(usize::from(dci)))
            .and_then(Option::as_mut)
            .ok_or(UsbError::EndpointNotFound)?;
        if !matches!(endpoint.state, EndpointState::Idle) {
            return Err(UsbError::NoResources);
        }
        let queue = endpoint.ring.identity();
        let control = matches!(kind, TransferKind::Control(_));
        let mut trbs = Vec::new();
        trbs.try_reserve_exact(length.div_ceil(65536) + 3)
            .map_err(|_| UsbError::NoResources)?;
        let mut addresses = Vec::new();
        addresses
            .try_reserve_exact(length.div_ceil(65536) + 3)
            .map_err(|_| UsbError::NoResources)?;
        let (memory, device_address) = if length != 0 {
            let direction = if direction_in {
                DmaDirection::FromDevice
            } else {
                DmaDirection::ToDevice
            };
            let mut memory = allocate_dma(self.pci_locator, length, direction)?;
            memory.write(|bytes| {
                bytes.fill(0);
                if let Some(source) = source {
                    bytes[..source.len()].copy_from_slice(source);
                }
            })?;
            let prepared = memory
                .prepare(queue)
                .map_err(|error| UsbError::CpuTransfer(Box::new(error)))?;
            let device_address = prepared.descriptor()?.device_address();
            let memory = prepared
                .arm()
                .map_err(|error| UsbError::PreparedTransfer(Box::new(error)))?;
            (Some(memory), device_address)
        } else {
            (None, DmaDeviceAddress::from_abi(0))
        };
        if let TransferKind::Control(setup) = &kind {
            if usize::from(setup.w_length) != length {
                return Err(UsbError::BufferSize);
            }
            trbs.push(Trb::setup_stage(
                setup,
                if length == 0 {
                    0
                } else if direction_in {
                    3
                } else {
                    2
                },
                true,
            ));
        }
        let mut offset = 0;
        // LOOP_PROOF: mode=condition; reason=Each iteration consumes at least one data byte, with transfer length bounded by the fixed ring capacity.;
        while offset < length {
            let address = device_address
                .checked_add(offset)
                .ok_or(UsbError::InvalidParameter)?
                .get();
            let count = (65536 - (address as usize & 65535)).min(length - offset);
            let mut trb = match kind {
                TransferKind::Control(_) if offset == 0 => {
                    Trb::data_stage(address, count as u32, direction_in, true)
                }
                TransferKind::Isochronous if offset == 0 => {
                    Trb::isoch_asap(address, count as u32, false, true)
                }
                _ => Trb::normal(address, count as u32, true),
            };
            let last = offset + count == length;
            trb.control &= !(1 << 5);
            if !last || control {
                trb.control |= 1 << 4;
            }
            if last && !control {
                trb.control |= 1 << 5;
            }
            if control {
                trb.control |= 1 << 2;
            }
            trbs.push(trb);
            offset += count;
        }
        if control {
            trbs.push(Trb::status_stage(length == 0 || !direction_in, true));
        }
        if trbs.is_empty() {
            trbs.push(Trb::normal(0, 0, true));
        }
        // Retain the DMA before a cycle write can make the TD observable. A
        // failed publication leaves a halted owner, never a released buffer.
        endpoint.state = EndpointState::Active(TransferRequest {
            addresses,
            receipt: Arc::clone(&receipt),
            memory,
            length,
            residual: None,
            control,
        });
        match endpoint.ring.enqueue_transfer(&trbs) {
            Ok(tail) => {
                let EndpointState::Active(request) = &mut endpoint.state else {
                    unreachable!()
                };
                // TD entries are contiguous except for the reserved Link TRB.
                let base = endpoint.ring.device_address();
                let capacity = TRANSFER_RING_SIZE - 1;
                let last = ((tail.get() - base.get()) / 16) as usize;
                for offset in (0..trbs.len()).rev() {
                    let index = (last + capacity - offset) % capacity;
                    request.addresses.push(
                        base.checked_add(index * 16)
                            .ok_or(UsbError::InvalidParameter)?,
                    );
                }
            }
            Err(error) => {
                let EndpointState::Active(request) =
                    core::mem::replace(&mut endpoint.state, EndpointState::Idle)
                else {
                    unreachable!()
                };
                endpoint.state = EndpointState::Halted(request);
                return Err(error.into());
            }
        }
        drop(endpoints);
        self.ring_doorbell(slot.0, dci)?;
        Ok(RequestFuture::new(self, receipt))
    }

    pub(super) fn finish_transfer_buffer(
        &self,
        result: TransferCompletionResult,
        destination: Option<&mut [u8]>,
    ) -> UsbResult<usize> {
        if let Some(memory) = result.memory {
            let read_result = if let Some(destination) = destination {
                if destination.len() < result.transferred {
                    return Err(UsbError::BufferSize);
                }
                memory.read(|bytes| {
                    destination[..result.transferred].copy_from_slice(&bytes[..result.transferred])
                })
            } else {
                Ok(())
            };
            if let Err(error) = memory.close() {
                let cause = error.cause();
                self.retirement_failures.lock().push(error);
                return Err(UsbError::Dma(cause));
            }
            read_result?;
        }
        Ok(result.transferred)
    }

    /// ポート状態変更イベントを処理
    fn handle_port_status_change(&self, event: &PortStatusChangeEvent) {
        let _port_id = event.port_id;
        // ポート状態変更の処理は別途実装
    }

    /// Publishes a doorbell through its retained register capability.
    pub(crate) fn ring_doorbell(&self, slot_id: u8, target: u8) -> UsbResult<()> {
        self.registers.ring_doorbell(slot_id, target)
    }
}

fn allocate_dma(
    device: PackedPciLocation,
    bytes: usize,
    direction: DmaDirection,
) -> UsbResult<CpuDmaLease> {
    let request = DmaAllocationRequest::new(bytes.next_multiple_of(64), direction)
        .ok_or(UsbError::InvalidParameter)?;
    kernel_api::service::kernel::instance()
        .alloc_dma_for_device(request, device)
        .map_err(UsbError::Allocation)
}

fn queue_identity(device: PackedPciLocation, index: u16) -> UsbResult<DmaQueueIdentity> {
    DmaQueueIdentity::new(device, index, 1).ok_or(UsbError::InvalidDevice)
}

enum CompletionWake {
    Command(Arc<Receipt<CommandCompletionResult>>),
    Transfer(Arc<Receipt<TransferCompletionResult>>),
}
impl CompletionWake {
    fn notify(self) {
        match self {
            Self::Command(receipt) => receipt.notify(),
            Self::Transfer(receipt) => receipt.notify(),
        }
    }
}
