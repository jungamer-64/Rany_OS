use super::{VirtioNetDevice, VirtioNetError};
use crate::io::virtio::transport::VirtioMmioTransport;
use crate::io::virtio::transport::VirtioTransport;
use crate::task::{spawn, wait_for_interrupt, InterruptSource};
use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::sync::Arc;
use spin::RwLock;
use alloc::collections::BTreeMap;

// ============================================================================
// Global Device Instance
// ============================================================================

/// Primary (legacy) VirtIO-Net device slot kept for compatibility (`index=0`).
pub(crate) static VIRTIO_NET_DEVICE: crate::sync::PoisonLock<Option<VirtioNetDevice>> = crate::sync::PoisonLock::new(None);
/// Additional VirtIO-Net devices (`index != 0`).
pub(crate) static VIRTIO_NET_DEVICES: RwLock<BTreeMap<u8, Arc<crate::sync::PoisonLock<VirtioNetDevice>>>> =
    RwLock::new(BTreeMap::new());
/// ISR-safe access to transport layer for interrupt acknowledgement.
pub(crate) static VIRTIO_NET_TRANSPORTS: RwLock<BTreeMap<u8, Arc<dyn VirtioTransport>>> =
    RwLock::new(BTreeMap::new());

fn install_virtio_net_device(index: u8, device: VirtioNetDevice) {
    let transport = device.transport.clone();
    if index == 0 {
        *VIRTIO_NET_DEVICE.lock().expect("VIRTIO_NET_DEVICE lock poisoned") = Some(device);
    } else {
        VIRTIO_NET_DEVICES
            .write()
            .insert(index, Arc::new(crate::sync::PoisonLock::new(device)));
    }
    VIRTIO_NET_TRANSPORTS.write().insert(index, transport);
    
    // ポスト・インタラプト（BH）ワーカータスクを起動
    spawn_virtio_net_worker(index);
}

/// VirtIO-Net の割り込み後処理を行うワーカータスクを起動する
fn spawn_virtio_net_worker(index: u8) {
    spawn(virtio_net_worker_task(index));
}

/// VirtIO-Net の割り込み後処理ループ
async fn virtio_net_worker_task(index: u8) {
    log::info!("[VIRTIO-NET] Worker task for index {} started", index);
    loop {
        // 1. 割り込みを待機
        wait_for_interrupt(InterruptSource::VirtioNet(index)).await;
        
        // 2. デバイスをロックして後処理（非ISRコンテキストなので安全）
        let result = with_virtio_net_device_at_index(index, |device| {
            device.handle_interrupt();
            // スタベーション回復: 不足しているRXバッファを補充
            device.refill_rx_queues();
        });
        
        if result.is_none() {
            log::warn!("[VIRTIO-NET] Worker task index {} exiting (device removed)", index);
            break;
        }
    }
}

pub(crate) fn with_virtio_net_device_at_index<F, R>(index: u8, f: F) -> Option<R>
where
    F: FnOnce(&VirtioNetDevice) -> R,
{
    if index == 0 {
        return VIRTIO_NET_DEVICE.lock().expect("VIRTIO_NET_DEVICE lock poisoned").as_ref().map(f);
    }

    let device = VIRTIO_NET_DEVICES.read().get(&index).cloned()?;
    let guard = device.lock().expect("virtqueue lock poisoned");
    Some(f(&guard))
}

fn with_virtio_net_device_at_index_mut<F, R>(index: u8, f: F) -> Option<R>
where
    F: FnOnce(&mut VirtioNetDevice) -> R,
{
    if index == 0 {
        let mut guard = VIRTIO_NET_DEVICE.lock().expect("VIRTIO_NET_DEVICE lock poisoned");
        return guard.as_mut().map(f);
    }

    let device = VIRTIO_NET_DEVICES.read().get(&index).cloned()?;
    let mut guard = device.lock().expect("virtqueue lock poisoned");
    Some(f(&mut guard))
}

pub(crate) fn has_virtio_net_device(index: u8) -> bool {
    if index == 0 {
        return VIRTIO_NET_DEVICE.lock().expect("VIRTIO_NET_DEVICE lock poisoned").is_some();
    }
    VIRTIO_NET_DEVICES.read().contains_key(&index)
}

fn collect_registered_virtio_net_indices() -> Vec<u8> {
    let mut indices = Vec::new();
    if VIRTIO_NET_DEVICE.lock().expect("VIRTIO_NET_DEVICE lock poisoned").is_some() {
        indices.push(0);
    }
    indices.extend(VIRTIO_NET_DEVICES.read().keys().copied());
    indices
}

/// VirtIO ネットワークデバイス（MMIO）を index 指定で初期化
pub fn init_virtio_net_at_index(index: u8, base_addr: usize) -> Result<(), VirtioNetError> {
    let transport =
        unsafe { VirtioMmioTransport::new(base_addr).map_err(|_| VirtioNetError::DeviceError)? };

    let mut device = VirtioNetDevice::new_at_index(index, Box::new(transport));
    device.init()?;
    install_virtio_net_device(index, device);
    Ok(())
}

/// VirtIO ネットワークデバイス（MMIO）を初期化
pub fn init_virtio_net(base_addr: usize) -> Result<(), VirtioNetError> {
    init_virtio_net_at_index(0, base_addr)
}

/// VirtIO ネットワークデバイス（MMIO）を index + IOMMUデバイスID指定で初期化
pub fn init_virtio_net_for_device_at_index(
    index: u8,
    base_addr: usize,
    device: crate::io::iommu::types::DeviceId,
) -> Result<(), VirtioNetError> {
    let transport =
        unsafe { VirtioMmioTransport::new(base_addr).map_err(|_| VirtioNetError::DeviceError)? };

    let mut device =
        VirtioNetDevice::new_with_index_and_device(index, Box::new(transport), Some(device));
    device.init()?;
    install_virtio_net_device(index, device);
    Ok(())
}

/// VirtIO ネットワークデバイス（MMIO）を初期化（IOMMUデバイスID付き）
pub fn init_virtio_net_for_device(
    base_addr: usize,
    device: crate::io::iommu::types::DeviceId,
) -> Result<(), VirtioNetError> {
    init_virtio_net_for_device_at_index(0, base_addr, device)
}

/// Initialize VirtIO-Net from an existing VirtioTransport (MMIO or PCI).
pub fn init_virtio_net_with_transport_at_index(
    index: u8,
    transport: Box<dyn VirtioTransport>,
    iommu_device_id: Option<crate::io::iommu::types::DeviceId>,
) -> Result<(), VirtioNetError> {
    let mut device = VirtioNetDevice::new_with_index_and_device(index, transport, iommu_device_id);
    device.init()?;
    install_virtio_net_device(index, device);
    Ok(())
}

/// Initialize VirtIO-Net from an existing VirtioTransport (MMIO or PCI).
pub fn init_virtio_net_with_transport(
    transport: Box<dyn VirtioTransport>,
    iommu_device_id: Option<crate::io::iommu::types::DeviceId>,
) -> Result<(), VirtioNetError> {
    init_virtio_net_with_transport_at_index(0, transport, iommu_device_id)
}

/// VirtIO ネットワークデバイスに index 指定でアクセス
pub fn with_virtio_net_at_index<F, R>(index: u8, f: F) -> Option<R>
where
    F: FnOnce(&VirtioNetDevice) -> R,
{
    with_virtio_net_device_at_index(index, f)
}

/// Bind a VirtIO-Net device index to a logical network interface id.
pub fn bind_virtio_net_interface(index: u8, if_id: crate::net::runtime::manager::NetIfId) -> bool {
    with_virtio_net_device_at_index_mut(index, |device| {
        device.set_net_if_id(if_id);
    })
    .is_some()
}

/// 登録済み VirtIO-Net デバイスを列挙して処理する。
pub fn for_each_virtio_net<F>(mut f: F)
where
    F: FnMut(u8, &VirtioNetDevice),
{
    let indices = collect_registered_virtio_net_indices();
    for index in indices {
        let _ = with_virtio_net_device_at_index(index, |device| {
            f(index, device);
        });
    }
}

/// VirtIO ネットワークデバイスにアクセス
pub fn with_virtio_net<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&VirtioNetDevice) -> R,
{
    with_virtio_net_device_at_index(0, f)
}

/// 指定 index の VirtIO-Net 割り込みを処理する。
///
/// 重要: この関数は ISR (Interrupt Service Routine) コンテキストから呼ばれる。
/// デッドロックを避けるため、デバイス全体のロックを取得してはならない。
pub fn handle_virtio_net_interrupt_for_index(index: u8) {
    // 1. ISR安全なトランスポートレジストリから取得
    let transport = VIRTIO_NET_TRANSPORTS.read().get(&index).cloned();
    
    if let Some(transport) = transport {
        // 2. 割り込みステータスを確認してACK（ISR安全）
        let status = transport.get_interrupt_status();
        if status != 0 {
            transport.ack_interrupt(status);
            
            // 3. Wakerを叩いてワーカータスクに後処理を委ねる（ISR安全）
            // これにより、デバイスロック取得に伴うデッドロックを回避する。
            crate::task::interrupt_waker::wake_from_interrupt(
                crate::task::interrupt_waker::InterruptSource::VirtioNet(index),
            );
        }
    }
}

/// Acknowledge a VirtIO-Net interrupt without processing queues.
pub fn ack_virtio_net_interrupt_for_index(index: u8) -> bool {
    let transport = VIRTIO_NET_TRANSPORTS.read().get(&index).cloned();
    if let Some(transport) = transport {
        let status = transport.get_interrupt_status();
        if status != 0 {
            transport.ack_interrupt(status);
            true
        } else {
            false
        }
    } else {
        false
    }
}

/// Acknowledge all registered VirtIO-Net interrupt sources.
pub fn ack_all_virtio_net_interrupts() -> bool {
    let indices = collect_registered_virtio_net_indices();
    let mut had_pending = false;
    for index in indices {
        had_pending |= ack_virtio_net_interrupt_for_index(index);
    }
    had_pending
}

/// 登録済みの全 VirtIO-Net デバイス割り込みを処理する（共有IRQ向け）。
pub fn handle_all_virtio_net_interrupts() {
    let indices = collect_registered_virtio_net_indices();
    for index in indices {
        handle_virtio_net_interrupt_for_index(index);
    }
}

/// 割り込みハンドラ
pub fn handle_virtio_net_interrupt() {
    handle_all_virtio_net_interrupts();
}

#[cfg(test)]
pub(crate) fn clear_virtio_net_devices_for_tests() {
    *VIRTIO_NET_DEVICE.lock().expect("VIRTIO_NET_DEVICE lock poisoned") = None;
    VIRTIO_NET_DEVICES.write().clear();
}
