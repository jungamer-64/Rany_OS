// ============================================================================
// kernel/src/net/drivers/virtio_runtime.rs - ドライバ / VirtIOランタイム
// ============================================================================

use alloc::sync::Arc;
use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::dma::{CpuOwned, DmaSlice};
use kernel_api::error::{KapiError, KapiResult};
use kernel_api::netdev::{NetPortId, NetPortRegistration};
use kernel_api::resource::net::PacketRef;

use crate::io::iommu::api::unmap_for_device;
use crate::io::iommu::types::DeviceId as IommuDeviceId;

const VIRTIO_PORT_ID_BASE: u64 = 0x0001_0000;

fn virtio_port_id(index: u8) -> NetPortId {
    NetPortId::new(VIRTIO_PORT_ID_BASE | index as u64)
}

struct KernelVirtioNetRuntime {
    device_index: u8,
    pci_locator: PackedPciLocation,
    iommu_device_id: IommuDeviceId,
}

impl KernelVirtioNetRuntime {
    fn new(device_index: u8, pci_locator: PackedPciLocation) -> Self {
        Self {
            device_index,
            pci_locator,
            iommu_device_id: iommu_device_from_pci_locator(pci_locator),
        }
    }
}

fn iommu_device_from_pci_locator(pci_locator: PackedPciLocation) -> IommuDeviceId {
    IommuDeviceId::new(
        pci_locator.segment(),
        pci_locator.bus(),
        pci_locator.device(),
        pci_locator.function(),
    )
}

fn dma_direction_for_net(
    direction: virtio_driver::net::NetDmaDirection,
) -> crate::io::dma::DmaDirection {
    match direction {
        virtio_driver::net::NetDmaDirection::ToDevice => crate::io::dma::DmaDirection::ToDevice,
        virtio_driver::net::NetDmaDirection::FromDevice => crate::io::dma::DmaDirection::FromDevice,
        virtio_driver::net::NetDmaDirection::Bidirectional => {
            crate::io::dma::DmaDirection::Bidirectional
        }
    }
}

fn map_net_dma_for_packet(
    device: IommuDeviceId,
    packet: &PacketRef,
    direction: virtio_driver::net::NetDmaDirection,
) -> Result<virtio_driver::net::NetDmaMappingToken, virtio_driver::net::VirtioNetError> {
    let ctx = crate::io::dma::DeviceDmaContext::for_attached_device(device);
    let mapping = ctx
        .map_physical_range(
            x86_64::PhysAddr::new(packet.phys_addr().as_u64()),
            packet.capacity(),
            dma_direction_for_net(direction),
        )
        .map_err(|_| virtio_driver::net::VirtioNetError::DeviceError)?;
    let device_addr = mapping.device_addr();
    let (_device_id, release_key, mapped_len) = mapping.into_parts();
    Ok(virtio_driver::net::NetDmaMappingToken::mapped(
        device_addr,
        release_key,
        mapped_len,
    ))
}

fn release_net_dma_mapping(device: IommuDeviceId, mapping: virtio_driver::net::NetDmaMappingToken) {
    if let Some(release_key) = mapping.release_key() {
        if let Err(err) = unmap_for_device(&device, release_key, mapping.mapped_len()) {
            log::warn!("[VIRTIO-NET] failed to unmap DMA buffer: {:?}", err);
        }
    }
}

impl virtio_driver::net::NetRuntime for KernelVirtioNetRuntime {
    fn alloc_dma(
        &self,
        size: usize,
        _purpose: virtio_driver::net::NetDmaPurpose,
    ) -> Result<DmaSlice<CpuOwned>, virtio_driver::net::VirtioNetError> {
        kernel_api::service::kernel::instance()
            .alloc_dma_for_device(size, self.pci_locator)
            .map_err(|_| virtio_driver::net::VirtioNetError::DeviceError)
    }

    fn alloc_packet(&self) -> Option<PacketRef> {
        crate::net::datapath::mempool::alloc_packet()
    }

    fn map_packet(
        &self,
        packet: &PacketRef,
        direction: virtio_driver::net::NetDmaDirection,
    ) -> Result<virtio_driver::net::NetDmaMappingToken, virtio_driver::net::VirtioNetError> {
        map_net_dma_for_packet(self.iommu_device_id, packet, direction)
    }

    fn release_dma_mapping(&self, mapping: virtio_driver::net::NetDmaMappingToken) {
        release_net_dma_mapping(self.iommu_device_id, mapping);
    }

    fn receive_packet(
        &self,
        _queue_index: u16,
        packet: PacketRef,
        header_len: usize,
        payload_len: usize,
    ) {
        if let Some(if_id) = crate::net::runtime::device::lookup_if_by_port_id_in(
            crate::net::runtime::default_runtime(),
            virtio_port_id(self.device_index),
        ) {
            crate::net::runtime::bridge::process_received_packet_zero_copy_for_interface_in(
                crate::net::runtime::default_runtime(),
                if_id,
                packet,
                header_len,
                payload_len,
            );
        } else {
            crate::net::runtime::bridge::process_received_packet_zero_copy_in(
                crate::net::runtime::default_runtime(),
                packet,
                header_len,
                payload_len,
            );
        }
    }

    fn transmit_complete(&self, _queue_index: u16, lease_id: kernel_api::netdev::TxLeaseId) {
        let _ = crate::net::runtime::device::complete_tx_lease_in(
            crate::net::runtime::default_runtime(),
            lease_id,
            Ok(()),
        );
        crate::net::runtime::command::enqueue_command_ignore(
            crate::net::runtime::command::RuntimeCommand::Transport(crate::net::runtime::command::TransportCommand::TxAvailable),
        );
    }

    fn schedule_wake(&self, queue_index: u16) {
        let _ = crate::net::runtime::device::enqueue_event(
            virtio_port_id(self.device_index),
            kernel_api::service::netdev::NetDriverEvent::QueueWake { queue_index },
        );
    }

    fn log(&self, level: log::Level, msg: core::fmt::Arguments) {
        log::log!(level, "[VIRTIO-NET] {}", msg);
    }
}

pub fn kernel_virtio_net_runtime_for_pci(
    device_index: u8,
    pci_locator: PackedPciLocation,
) -> KapiResult<Arc<dyn virtio_driver::net::NetRuntime>> {
    Ok(Arc::new(KernelVirtioNetRuntime::new(
        device_index,
        pci_locator,
    )))
}

pub fn register_kernel_virtio_net_port(
    index: u8,
    registration: NetPortRegistration,
) -> KapiResult<()> {
    let if_id = crate::net::runtime::device::register_port(registration).map_err(|err| {
        log::error!(
            target: "net",
            "Failed to register VirtIO-Net port {}: {}",
            index,
            err
        );
        KapiError::IoError
    })?;

    crate::net::runtime::bridge::register_stack_glue_interface_in(
        crate::net::runtime::default_runtime(),
        if_id,
    );
    crate::io::io_scheduler::virtio_net::register_virtio_net_with_io_scheduler(index);
    Ok(())
}

pub fn kernel_virtio_net_driver_hooks() -> virtio_driver::net::driver::VirtioNetDriverHooks {
    virtio_driver::net::driver::VirtioNetDriverHooks::new(
        kernel_virtio_net_runtime_for_pci,
        register_kernel_virtio_net_port,
    )
}
