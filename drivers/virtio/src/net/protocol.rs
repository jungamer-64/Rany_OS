//! Configuration is captured under one device generation. Packet admission
//! precedes descriptor publication and never reads or copies packet payload.
#![forbid(unsafe_code)]

use core::num::NonZeroU16;
use kernel_api::abi::driver::{AbiError, AbiNetRxFrameLayout, AbiNetTxSegments};
use kernel_api::resource::net::PacketByteCount;

use super::features::*;
use crate::defs::{common_features, status};
use crate::transport::{TransportError, VirtioTransport};

pub const NET_HEADER_BYTES: usize = 12;
const ETHERNET_HEADER_BYTES: usize = 14;
const DEFAULT_MTU: u16 = 1500;

pub const NET_SUPPORTED_FEATURES: u64 = common_features::VIRTIO_F_VERSION_1
    | common_features::VIRTIO_F_ACCESS_PLATFORM
    | VIRTIO_NET_F_MAC
    | VIRTIO_NET_F_STATUS
    | VIRTIO_NET_F_MTU
    | VIRTIO_NET_F_CTRL_VQ
    | VIRTIO_NET_F_MQ;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetConfigurationError {
    Features,
    Transport(TransportError),
    GenerationChanged,
    InvalidMac,
    InvalidMtu,
    InvalidQueuePairs,
}

#[derive(Clone, Copy, Debug)]
pub struct NetConfiguration {
    features: u64,
    mac: [u8; 6],
    mtu: u16,
    offered_pairs: NonZeroU16,
}

impl NetConfiguration {
    /// Read configuration after feature acceptance, before publishing queues.
    /// `fallback_mac` is a locally administered address owned by this instance.
    ///
    /// # Errors
    /// Rejects unsupported features, inconsistent generations and invalid
    /// geometry before authorizing packet or queue admission.
    pub fn read(
        transport: &dyn VirtioTransport,
        features: u64,
        fallback_mac: [u8; 6],
    ) -> Result<Self, NetConfigurationError> {
        validate_features(features)?;
        if transport.status() & status::VIRTIO_STATUS_FEATURES_OK == 0 {
            return Err(NetConfigurationError::Features);
        }
        let generation = transport.config_generation();
        let mut mac = fallback_mac;
        if features & VIRTIO_NET_F_MAC != 0 {
            for (offset, octet) in mac.iter_mut().enumerate() {
                *octet = transport
                    .read_config_u8(offset)
                    .map_err(NetConfigurationError::Transport)?;
            }
        }
        let mtu = if features & VIRTIO_NET_F_MTU != 0 {
            transport
                .read_config_u16(10)
                .map_err(NetConfigurationError::Transport)?
        } else {
            DEFAULT_MTU
        };
        let pairs = if features & VIRTIO_NET_F_MQ != 0 {
            transport
                .read_config_u16(8)
                .map_err(NetConfigurationError::Transport)?
        } else {
            1
        };
        if generation != transport.config_generation() {
            return Err(NetConfigurationError::GenerationChanged);
        }
        Self::from_values(features, mac, mtu, pairs)
    }

    fn from_values(
        features: u64,
        mac: [u8; 6],
        mtu: u16,
        pairs: u16,
    ) -> Result<Self, NetConfigurationError> {
        validate_features(features)?;
        if mac == [0; 6] || mac[0] & 1 != 0 || (features & VIRTIO_NET_F_MAC == 0 && mac[0] & 2 == 0)
        {
            return Err(NetConfigurationError::InvalidMac);
        }
        if mtu < 68 || mtu.checked_add(ETHERNET_HEADER_BYTES as u16).is_none() {
            return Err(NetConfigurationError::InvalidMtu);
        }
        let offered_pairs = NonZeroU16::new(pairs)
            .filter(|pairs| pairs.get() <= 0x8000)
            .ok_or(NetConfigurationError::InvalidQueuePairs)?;
        if features & VIRTIO_NET_F_MQ == 0 && pairs != 1 {
            return Err(NetConfigurationError::InvalidQueuePairs);
        }
        Ok(Self {
            features,
            mac,
            mtu,
            offered_pairs,
        })
    }

    pub const fn mac(&self) -> [u8; 6] {
        self.mac
    }

    pub const fn mtu(&self) -> u16 {
        self.mtu
    }

    pub const fn offered_pairs(&self) -> NonZeroU16 {
        self.offered_pairs
    }

    pub const fn maximum_frame_bytes(&self) -> usize {
        self.mtu as usize + ETHERNET_HEADER_BYTES
    }

    pub const fn receive_buffer_bytes(&self) -> usize {
        NET_HEADER_BYTES + self.maximum_frame_bytes()
    }

    pub const fn has_control_queue(&self) -> bool {
        self.features & VIRTIO_NET_F_CTRL_VQ != 0
    }

    /// The control queue follows all offered pairs, including inactive pairs.
    ///
    /// # Errors
    /// Rejects a missing control queue or an index outside the transport's u16
    /// selector, before acquiring any register or DMA authority.
    pub fn control_queue_index(&self) -> Result<u16, NetConfigurationError> {
        if !self.has_control_queue() {
            return Err(NetConfigurationError::Features);
        }
        self.offered_pairs
            .get()
            .checked_mul(2)
            .ok_or(NetConfigurationError::InvalidQueuePairs)
    }

    /// # Errors
    /// Preserves register failures and configuration-generation changes.
    pub fn link_up(&self, transport: &dyn VirtioTransport) -> Result<bool, NetConfigurationError> {
        if self.features & VIRTIO_NET_F_STATUS == 0 {
            return Ok(true);
        }
        let generation = transport.config_generation();
        let link = transport
            .read_config_u16(6)
            .map_err(NetConfigurationError::Transport)?;
        if generation != transport.config_generation() {
            return Err(NetConfigurationError::GenerationChanged);
        }
        Ok(link & VIRTIO_NET_S_LINK_UP != 0)
    }

    /// Validate every retained scatter-gather extent without touching payload.
    ///
    /// # Errors
    /// Rejects descriptor fan-out, overflowing address/length and MTU excess.
    pub fn admit_transmit(
        &self,
        segments: AbiNetTxSegments<'_>,
        maximum_segments: usize,
    ) -> Result<PacketByteCount, AbiError> {
        if segments.count() > maximum_segments {
            return Err(AbiError::NotSupported);
        }
        let mut bytes = 0usize;
        for segment in segments.iter() {
            let length = u32::try_from(segment.len().get()).map_err(|_| AbiError::InvalidParam)?;
            if segment.device_addr() == 0
                || segment
                    .device_addr()
                    .checked_add(u64::from(length))
                    .is_none()
            {
                return Err(AbiError::InvalidAddress);
            }
            bytes = bytes
                .checked_add(segment.len().get())
                .ok_or(AbiError::InvalidParam)?;
        }
        if !(ETHERNET_HEADER_BYTES..=self.maximum_frame_bytes()).contains(&bytes) {
            return Err(AbiError::InvalidParam);
        }
        PacketByteCount::new(bytes).ok_or(AbiError::InvalidParam)
    }

    /// Interpret a completed, unmerged, fully checksummed device frame.
    ///
    /// # Errors
    /// Rejects truncated/oversized frames and unnegotiated checksum/GSO work.
    pub fn receive_layout(
        &self,
        header: [u8; NET_HEADER_BYTES],
        written: u32,
        capacity: usize,
    ) -> Result<AbiNetRxFrameLayout, AbiError> {
        let written = usize::try_from(written).map_err(|_| AbiError::InvalidParam)?;
        if written > capacity || written < NET_HEADER_BYTES + ETHERNET_HEADER_BYTES {
            return Err(AbiError::IoError);
        }
        if header[0] != 0 || header[1] != 0 {
            return Err(AbiError::NotSupported);
        }
        let payload = written - NET_HEADER_BYTES;
        if payload > self.maximum_frame_bytes() {
            return Err(AbiError::IoError);
        }
        AbiNetRxFrameLayout::new(written, NET_HEADER_BYTES, payload).ok_or(AbiError::InvalidParam)
    }

    /// # Errors
    /// Rejects multiqueue use without its negotiated control protocol, zero
    /// pairs, and requests beyond the advertised queue range.
    pub fn queue_pair_command(
        &self,
        pairs: NonZeroU16,
    ) -> Result<QueuePairCommand, NetConfigurationError> {
        if self.features & VIRTIO_NET_F_MQ == 0 || pairs > self.offered_pairs {
            return Err(NetConfigurationError::InvalidQueuePairs);
        }
        self.control_queue_index()?;
        Ok(QueuePairCommand { pairs })
    }
}

fn validate_features(features: u64) -> Result<(), NetConfigurationError> {
    let mandatory = common_features::VIRTIO_F_VERSION_1 | common_features::VIRTIO_F_ACCESS_PLATFORM;
    if features & mandatory != mandatory
        || features & !NET_SUPPORTED_FEATURES != 0
        || (features & VIRTIO_NET_F_MQ != 0 && features & VIRTIO_NET_F_CTRL_VQ == 0)
    {
        return Err(NetConfigurationError::Features);
    }
    Ok(())
}

/// One admitted control operation; a device acknowledgement consumes it once.
#[derive(Debug)]
pub struct QueuePairCommand {
    pairs: NonZeroU16,
}

impl QueuePairCommand {
    pub(crate) const fn pairs(&self) -> NonZeroU16 {
        self.pairs
    }
    pub const fn encode(&self) -> [u8; 4] {
        let pairs = self.pairs.get().to_le_bytes();
        [4, 0, pairs[0], pairs[1]]
    }

    /// # Errors
    /// Returns this request for malformed or rejected acknowledgements.
    pub(crate) fn acknowledge(self, written: u32, status: u8) -> Result<EnabledQueuePairs, Self> {
        if written != 1 || status != 0 {
            return Err(self);
        }
        Ok(EnabledQueuePairs { pairs: self.pairs })
    }
}

#[derive(Debug)]
pub struct EnabledQueuePairs {
    pairs: NonZeroU16,
}

impl EnabledQueuePairs {
    pub const fn count(&self) -> NonZeroU16 {
        self.pairs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configuration() -> NetConfiguration {
        NetConfiguration::from_values(NET_SUPPORTED_FEATURES, [2, 1, 2, 3, 4, 5], 1500, 4).unwrap()
    }

    #[test]
    fn queue_enable_requires_one_successful_device_acknowledgement() {
        let config = configuration();
        assert_eq!(config.control_queue_index(), Ok(8));
        let request = config
            .queue_pair_command(NonZeroU16::new(3).unwrap())
            .unwrap();
        assert_eq!(request.encode(), [4, 0, 3, 0]);
        let request = request.acknowledge(0, 0).unwrap_err();
        let request = request.acknowledge(1, 1).unwrap_err();
        assert_eq!(request.acknowledge(1, 0).unwrap().count().get(), 3);
    }

    #[test]
    fn configuration_rejects_invalid_hardware_geometry_and_feature_dependencies() {
        assert_eq!(
            validate_features(NET_SUPPORTED_FEATURES & !VIRTIO_NET_F_CTRL_VQ),
            Err(NetConfigurationError::Features)
        );
        for pairs in [0, 0x8001] {
            assert!(matches!(
                NetConfiguration::from_values(NET_SUPPORTED_FEATURES, [2; 6], 1500, pairs),
                Err(NetConfigurationError::InvalidQueuePairs)
            ));
        }
        assert!(matches!(
            NetConfiguration::from_values(NET_SUPPORTED_FEATURES, [1; 6], 1500, 1),
            Err(NetConfigurationError::InvalidMac)
        ));
        assert!(matches!(
            NetConfiguration::from_values(NET_SUPPORTED_FEATURES, [2; 6], 67, 1),
            Err(NetConfigurationError::InvalidMtu)
        ));
    }

    #[test]
    fn completed_frame_preserves_the_packet_window_and_excludes_unwritten_tail() {
        let config = configuration();
        let layout = config
            .receive_layout([0; NET_HEADER_BYTES], 76, 2048)
            .unwrap();
        assert_eq!(layout.frame_len(), 76);
        assert_eq!(layout.header_len(), 12);
        assert_eq!(layout.payload_len(), 64);
        for length in [0, 12, 25, 2049] {
            assert_eq!(
                config
                    .receive_layout([0; NET_HEADER_BYTES], length, 2048)
                    .unwrap_err(),
                AbiError::IoError
            );
        }
        let mut header = [0; NET_HEADER_BYTES];
        header[0] = 1;
        assert_eq!(
            config.receive_layout(header, 76, 2048).unwrap_err(),
            AbiError::NotSupported
        );
        header[0] = 2;
        assert_eq!(
            config.receive_layout(header, 76, 2048).unwrap_err(),
            AbiError::NotSupported
        );
        header[0] = 0;
        header[1] = 1;
        assert_eq!(
            config.receive_layout(header, 76, 2048).unwrap_err(),
            AbiError::NotSupported
        );
    }

    #[test]
    fn fragmented_transmit_obeys_fanout_mtu_and_address_bounds_before_publication() {
        use kernel_api::abi::driver::{AbiNetTxSegment, AbiNetTxSegments};
        let configuration = configuration();
        let first = [0xa1; 64];
        let second = [0xb2; 64];
        let descriptors = [
            AbiNetTxSegment::from_checked_parts(
                first.as_ptr(),
                0x1000,
                PacketByteCount::new(first.len()).unwrap(),
            )
            .unwrap(),
            AbiNetTxSegment::from_checked_parts(
                second.as_ptr(),
                0x2000,
                PacketByteCount::new(second.len()).unwrap(),
            )
            .unwrap(),
        ];
        let segments = AbiNetTxSegments::new(&descriptors).unwrap();
        assert_eq!(
            configuration.admit_transmit(segments, 2).unwrap().get(),
            128
        );
        assert_eq!(
            configuration.admit_transmit(segments, 1).unwrap_err(),
            AbiError::NotSupported
        );
        let descriptors = [AbiNetTxSegment::from_checked_parts(
            first.as_ptr(),
            u64::MAX - 31,
            PacketByteCount::new(64).unwrap(),
        )
        .unwrap()];
        assert_eq!(
            configuration.admit_transmit(AbiNetTxSegments::new(&descriptors).unwrap(), 2),
            Err(AbiError::InvalidAddress)
        );
        let too_large = [0; 1515];
        let descriptors = [AbiNetTxSegment::from_checked_parts(
            too_large.as_ptr(),
            0x3000,
            PacketByteCount::new(too_large.len()).unwrap(),
        )
        .unwrap()];
        assert_eq!(
            configuration.admit_transmit(AbiNetTxSegments::new(&descriptors).unwrap(), 2),
            Err(AbiError::InvalidParam)
        );
        let descriptors = [AbiNetTxSegment::from_checked_parts(
            first.as_ptr(),
            0x4000,
            PacketByteCount::new(13).unwrap(),
        )
        .unwrap()];
        assert_eq!(
            configuration.admit_transmit(AbiNetTxSegments::new(&descriptors).unwrap(), 2),
            Err(AbiError::InvalidParam)
        );
        assert_eq!(first, [0xa1; 64]);
        assert_eq!(second, [0xb2; 64]);
    }
}
