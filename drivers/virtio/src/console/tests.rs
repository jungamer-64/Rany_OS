use super::*;
use crate::defs::common_features;
use kernel_api::KapiError;

#[test]
fn negotiation_requires_translated_dma_and_admits_only_implemented_protocols() {
    let mandatory = common_features::VIRTIO_F_VERSION_1 | common_features::VIRTIO_F_ACCESS_PLATFORM;
    assert_eq!(device::select_features(u64::MAX), Ok(mandatory | 1 | 4));
    assert_eq!(device::select_features(mandatory), Ok(mandatory));
    assert_eq!(
        device::select_features(common_features::VIRTIO_F_VERSION_1),
        Err(KapiError::NotSupported)
    );
    assert_eq!(
        device::select_features(common_features::VIRTIO_F_ACCESS_PLATFORM),
        Err(KapiError::NotSupported)
    );
}
