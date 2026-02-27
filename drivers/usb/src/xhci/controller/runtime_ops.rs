#![allow(clippy::wildcard_imports)]
use super::*;

impl XhciController {
    pub(super) fn write_runtime(&self, offset: usize, value: u32) {
        hal::mmio::mmio_write_u32(
            (self.rt_offset + IR0 as u64 + offset as u64) as usize,
            value,
        );
    }

    pub(super) fn write_runtime_64(&self, offset: usize, value: u64) {
        hal::mmio::mmio_write_u64(
            (self.rt_offset + IR0 as u64 + offset as u64) as usize,
            value,
        );
    }

    /// ポート数を取得
    pub fn port_count(&self) -> u8 {
        self.max_ports
    }

    /// 転送完了待ちを登録
    pub(crate) fn register_transfer_wait(&self, slot_id: SlotId, endpoint_id: u8, waker: Waker) {
        let mut completions = self.transfer_completions.lock();
        completions.push(TransferCompletion {
            trb_addr: 0, // TRBアドレスは後で設定可能
            slot_id,
            endpoint_id,
            completion_code: CompletionCode::Invalid,
            transferred: 0,
            waker: Some(waker),
            completed: false,
        });
    }

    /// 転送完了を確認
    pub(crate) fn check_transfer_completion(
        &self,
        slot_id: SlotId,
        endpoint_id: u8,
    ) -> Option<TransferCompletionResult> {
        let mut completions = self.transfer_completions.lock();
        if let Some(pos) = completions
            .iter()
            .position(|c| c.slot_id == slot_id && c.endpoint_id == endpoint_id && c.completed)
        {
            let completion = completions.remove(pos);
            return Some(TransferCompletionResult {
                completion_code: completion.completion_code,
                transferred: completion.transferred,
            });
        }
        None
    }

    /// 転送完了待ちをキャンセル
    pub(crate) fn cancel_transfer_wait(&self, slot_id: SlotId, endpoint_id: u8) {
        let mut completions = self.transfer_completions.lock();
        completions
            .retain(|c| !(c.slot_id == slot_id && c.endpoint_id == endpoint_id && !c.completed));
    }

    // ========================================================================
    // Device Enumeration
    // ========================================================================

    /// デバイスコンテキストを割り当て
    ///
    /// DCBAAエントリを設定し、デバイスコンテキストを作成
    pub fn allocate_device_context(&self, slot_id: SlotId) -> UsbResult<()> {
        if !slot_id.is_valid() || slot_id.as_usize() > self.max_slots as usize {
            return Err(UsbError::InvalidDevice);
        }

        // デバイスコンテキストをDMAバッファで作成
        let ctx_size = core::mem::size_of::<DeviceContext>();
        let dma_buf = kernel_api::services::kernel()
            .alloc_dma(ctx_size)
            .map_err(|_| UsbError::Other("Failed to allocate DMA for DeviceContext".into()))?;
        let ctx_ptr = dma_buf.as_ptr() as *mut DeviceContext;
        let ctx_device_addr = dma_buf.device_address();

        // ゼロ初期化
        unsafe {
            core::ptr::write_bytes(ctx_ptr, 0, 1);
        }

        // DCBAAに登録 (デバイス可視アドレスで)
        // SAFETY: slot_id は max_slots 以下であることを確認済み
        unsafe {
            core::ptr::write_volatile(self.dcbaa_ptr.add(slot_id.as_usize()), ctx_device_addr);
        }

        // DMA-backedデバイスコンテキストを保存
        let dma_ctx = DmaDeviceContext {
            ptr: ctx_ptr,
            device_addr: ctx_device_addr,
            _dma_buf: dma_buf,
        };
        let mut device_contexts = self.device_contexts.lock();
        if slot_id.as_usize() < device_contexts.len() {
            device_contexts[slot_id.as_usize()] = Some(dma_ctx);
        }

        Ok(())
    }

    /// 転送リングを割り当て
    ///
    /// 指定されたスロット/エンドポイントに転送リングを作成
    pub fn allocate_transfer_ring(&self, slot_id: SlotId, dci: u8) -> UsbResult<u64> {
        if !slot_id.is_valid() || dci == 0 || dci > 31 {
            return Err(UsbError::InvalidDevice);
        }

        let ring = Box::new(TrbRing::new(TRANSFER_RING_SIZE));
        let ring_addr = ring.device_address();

        let mut transfer_rings = self.transfer_rings.lock();
        if let Some(slot_rings) = transfer_rings.get_mut(slot_id.as_usize()) {
            if let Some(endpoint_ring) = slot_rings.get_mut(dci as usize) {
                *endpoint_ring = Some(ring);
            }
        }

        Ok(ring_addr)
    }

    /// デバイスにアドレスを割り当て
    ///
    /// Address Device コマンドを発行してデバイスにアドレスを設定
    pub async fn address_device(
        &self,
        slot_id: SlotId,
        port: PortNumber,
        speed: UsbSpeed,
        block_set_address: bool,
    ) -> UsbResult<()> {
        use crate::xhci::context::InputContext;

        // EP0用の転送リングを割り当て
        let tr_dequeue_ptr = self.allocate_transfer_ring(slot_id, 1)?;

        // 速度に応じたデフォルトの最大パケットサイズ
        let max_packet_size = speed.default_max_packet_size();

        // 入力コンテキストを作成
        let input_context = InputContext::for_address_device(
            speed,
            0, // route_string (直接接続)
            port.one_indexed() as u8,
            max_packet_size,
            tr_dequeue_ptr,
        );

        // InputContextをDMAバッファにコピー
        let input_ctx_size = core::mem::size_of::<InputContext>();
        let input_dma_buf = kernel_api::services::kernel()
            .alloc_dma(input_ctx_size)
            .map_err(|_| UsbError::Other("Failed to allocate DMA for InputContext".into()))?;
        let input_dma_ptr = input_dma_buf.as_ptr() as *mut InputContext;
        unsafe {
            core::ptr::copy_nonoverlapping(&input_context as *const InputContext, input_dma_ptr, 1);
        }
        let input_context_ptr = input_dma_buf.device_address();

        // Address Device TRB を作成
        let cycle = self.command_ring.lock().cycle_bit();
        let trb = Trb::address_device(input_context_ptr, slot_id, block_set_address, cycle);

        // コマンドを送信
        let trb_addr = self.send_command(trb)?;

        // 完了を待機
        let completion = self.wait_command_completion(trb_addr).await?;

        if completion.completion_code == CompletionCode::Success {
            // DMAバッファを保持（ドロップ防止）
            core::mem::forget(input_dma_buf);
            Ok(())
        } else {
            Err(UsbError::XhciError(alloc::format!(
                "Address device failed: {:?}",
                completion.completion_code
            )))
        }
    }

    /// デバイスを列挙
    ///
    /// ポートに接続されたデバイスを完全に列挙:
    /// 1. スロットを有効化
    /// 2. デバイスコンテキストを割り当て
    /// 3. デバイスにアドレスを割り当て
    ///
    /// 成功時はスロットIDを返す
    pub async fn enumerate_device(&self, port: PortNumber) -> UsbResult<SlotId> {
        // ポートの状態を確認
        let status = self.port_status(port);
        if !status.connected {
            return Err(UsbError::NotConnected);
        }

        let speed = status
            .speed
            .ok_or(UsbError::Other("Unknown speed".into()))?;

        // ポートをリセット
        let _reset_speed = self.reset_port(port).await?;

        // スロットを有効化
        let slot_id = self.enable_slot().await?;

        // デバイスコンテキストを割り当て
        self.allocate_device_context(slot_id)?;

        // デバイスにアドレスを割り当て
        self.address_device(slot_id, port, speed, false).await?;

        Ok(slot_id)
    }

    /// エンドポイントを設定
    ///
    /// Configure Endpoint コマンドを発行してエンドポイントを有効化
    pub async fn configure_endpoints(
        &self,
        slot_id: SlotId,
        endpoints: &[(u8, crate::xhci::context::EndpointContext)],
    ) -> UsbResult<()> {
        use crate::xhci::context::InputContext;

        // 現在のスロットコンテキストを取得
        let device_contexts = self.device_contexts.lock();
        let slot_context = device_contexts
            .get(slot_id.as_usize())
            .and_then(|opt| opt.as_ref())
            .map(|ctx| ctx.context().slot)
            .ok_or(UsbError::InvalidDevice)?;
        drop(device_contexts);

        // 入力コンテキストを作成
        let input_context = InputContext::for_configure_endpoint(&slot_context, endpoints);

        // InputContextをDMAバッファにコピー
        let input_ctx_size = core::mem::size_of::<InputContext>();
        let input_dma_buf = kernel_api::services::kernel()
            .alloc_dma(input_ctx_size)
            .map_err(|_| UsbError::Other("Failed to allocate DMA for InputContext".into()))?;
        let input_dma_ptr = input_dma_buf.as_ptr() as *mut InputContext;
        unsafe {
            core::ptr::copy_nonoverlapping(&input_context as *const InputContext, input_dma_ptr, 1);
        }
        let input_context_ptr = input_dma_buf.device_address();

        // 各エンドポイント用の転送リングを割り当て
        for (dci, _) in endpoints {
            let tr_addr = self.allocate_transfer_ring(slot_id, *dci)?;
            // 既に設定済みの入力コンテキストのエンドポイントにTRアドレスを設定
            // (InputContext::for_configure_endpoint で設定されていると仮定)
            let _ = tr_addr;
        }

        // Configure Endpoint TRB を作成
        let cycle = self.command_ring.lock().cycle_bit();
        let trb = Trb::configure_endpoint(input_context_ptr, slot_id, cycle);

        // コマンドを送信
        let trb_addr = self.send_command(trb)?;

        // 完了を待機
        let completion = self.wait_command_completion(trb_addr).await?;

        if completion.completion_code == CompletionCode::Success {
            // DMAバッファを保持 (ドロップ防止)
            core::mem::forget(input_dma_buf);
            Ok(())
        } else {
            Err(UsbError::XhciError(alloc::format!(
                "Configure endpoint failed: {:?}",
                completion.completion_code
            )))
        }
    }

    /// 最大スロット数を取得
    pub fn max_slots(&self) -> u8 {
        self.max_slots
    }
}
