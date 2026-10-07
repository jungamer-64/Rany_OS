#![allow(clippy::wildcard_imports)]
use super::*;

impl XhciController {
    /// ポート数を取得
    pub fn port_count(&self) -> u8 {
        self.max_ports
    }

    // ========================================================================
    // Device Enumeration
    // ========================================================================

    /// デバイスコンテキストを割り当て
    ///
    /// DCBAAエントリを設定し、デバイスコンテキストを作成
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required device resources cannot be acquired.
    pub fn allocate_device_context(&self, slot_id: SlotId) -> UsbResult<()> {
        if !slot_id.is_valid() || slot_id.as_usize() > self.max_slots as usize {
            return Err(UsbError::InvalidDevice);
        }

        let mut contexts = self.device_contexts.lock();
        let entry = contexts
            .get_mut(slot_id.as_usize())
            .ok_or(UsbError::InvalidDevice)?;
        if entry.is_some() {
            return Err(UsbError::NoResources);
        }
        let context = SharedRegion::prepare(
            allocate_dma(
                self.pci_locator,
                32 * self.context_stride,
                DmaDirection::Bidirectional,
            )?,
            self.command_ring.lock().identity(),
            |bytes| bytes.fill(0),
        )?;
        let address = context.address;
        // Retain before publication so even a failed scalar store has an owner.
        *entry = Some(context);
        self.dcbaa
            .lock()
            .memory
            .window(slot_id.as_usize() * 8, 8)?
            .write_u64(0, address.get())?;

        Ok(())
    }

    /// 転送リングを割り当て
    ///
    /// 指定されたスロット/エンドポイントに転送リングを作成
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required device resources cannot be acquired.
    pub fn allocate_transfer_ring(&self, slot_id: SlotId, dci: u8) -> UsbResult<u64> {
        if !slot_id.is_valid() || dci == 0 || dci > 31 {
            return Err(UsbError::InvalidDevice);
        }

        let mut transfer_rings = self.transfer_rings.lock();
        let entry = transfer_rings
            .get_mut(slot_id.as_usize())
            .and_then(|rings| rings.get_mut(usize::from(dci)))
            .ok_or(UsbError::InvalidDevice)?;
        if entry.is_some() {
            return Err(UsbError::NoResources);
        }
        let ring = PreparedProducerRing::prepare(
            allocate_dma(
                self.pci_locator,
                TRANSFER_RING_SIZE * 16,
                DmaDirection::ToDevice,
            )?,
            queue_identity(
                self.pci_locator,
                2 + u16::from(slot_id.0) * 32 + u16::from(dci),
            )?,
            TRANSFER_RING_SIZE as u16,
        )?
        .activate()?;
        let ring_addr = ring.device_address().get();
        *entry = Some(Box::new(EndpointQueue {
            ring,
            state: EndpointState::Idle,
        }));
        Ok(ring_addr)
    }

    /// デバイスにアドレスを割り当て
    ///
    /// Address Device コマンドを発行してデバイスにアドレスを設定
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required device resources cannot be acquired.
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

        let request = self.send_input_command(&input_context, |address| {
            Trb::address_device(address, slot_id, block_set_address, true)
        })?;

        // 完了を待機
        let completion = request.await?;

        if completion.completion_code == CompletionCode::Success {
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
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required device resources cannot be acquired.
    pub async fn enumerate_device(&self, port: PortNumber) -> UsbResult<SlotId> {
        // ポートの状態を確認
        let status = self.port_status(port)?;
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
    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or rejected by the device.
    pub async fn configure_endpoints(
        &self,
        slot_id: SlotId,
        endpoints: &[(u8, crate::xhci::context::EndpointContext)],
    ) -> UsbResult<()> {
        use crate::xhci::context::InputContext;

        // 現在のスロットコンテキストを取得
        let mut device_contexts = self.device_contexts.lock();
        let slot_context = device_contexts
            .get_mut(slot_id.as_usize())
            .and_then(|opt| opt.as_mut())
            .map(SharedRegion::slot_context)
            .ok_or(UsbError::InvalidDevice)??;
        drop(device_contexts);

        let mut input_context = InputContext::for_configure_endpoint(&slot_context, endpoints);
        for (dci, _) in endpoints {
            if *dci == 0 || *dci > 31 {
                return Err(UsbError::InvalidParameter);
            }
            let address = self.allocate_transfer_ring(slot_id, *dci)?;
            input_context.endpoints[usize::from(*dci) - 1].tr_dequeue_ptr = address | 1;
        }
        let request = self.send_input_command(&input_context, |address| {
            Trb::configure_endpoint(address, slot_id, true)
        })?;

        // 完了を待機
        let completion = request.await?;

        if completion.completion_code == CompletionCode::Success {
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
