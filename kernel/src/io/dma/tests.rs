use super::*;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_typed_dma_buffer() {
    let buffer = TypedDmaBuffer::<u32, CpuOwned>::new(42).expect("Failed to allocate");

    // CPU所有状態ではアクセス可能
    assert_eq!(*buffer.as_ref(), 42);

    // DMA転送開始
    let (device_buffer, guard) = buffer.start_dma();
    let _phys = guard.phys_addr();

    // DeviceOwned状態では as_ref() がコンパイルエラーになる
    // （ここでは確認のためコメントアウト）
    // device_buffer.as_ref(); // ERROR!

    // DMA転送完了 (guard.complete(dev) を使用)
    let buffer = guard.complete(device_buffer);
    assert_eq!(*buffer.as_ref(), 42);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_typed_dma_slice() {
    let mut slice = TypedDmaSlice::<CpuOwned>::new(4096).expect("Failed to allocate");

    // データを書き込み
    {
        let s = slice.as_mut_slice();
        s[0] = 0xDE;
        s[1] = 0xAD;
    }

    // 確認
    assert_eq!(slice.as_slice()[0], 0xDE);
    assert_eq!(slice.as_slice()[1], 0xAD);

    // DMA転送
    let (device_slice, guard) = slice.start_dma();
    // device_slice.as_slice(); // ERROR! DeviceOwnedでは不可

    // DMA転送完了 (guard.complete(dev) を使用)
    let cpu_slice = guard.complete(device_slice);
    assert_eq!(cpu_slice.as_slice()[0], 0xDE);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_coherent_dma_export_preserves_metadata_and_reclaims_once() {
    reset_coherent_dma_export_release_count();

    let buffer =
        CoherentDmaBuffer::new(4096, DmaMemoryAttributes::MMIO).expect("allocate coherent DMA");
    let phys = buffer.phys_addr().as_u64();
    let device = buffer.device_addr();
    let len = buffer.size();
    let ptr = unsafe { buffer.as_slice().as_ptr() as *mut u8 };

    let exported = buffer.into_kernel_api_dma_slice();

    assert_eq!(exported.dma_handle_id(), 0);
    assert_eq!(exported.device_address(), device);
    assert_eq!(exported.size(), len);
    assert_eq!(exported.as_ptr(), ptr);
    drop(exported);

    assert_eq!(coherent_dma_export_release_count(), 1);
    assert_eq!(phys, device);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_coherent_dma_export_start_dma_complete_smoke() {
    reset_coherent_dma_export_release_count();

    let buffer =
        CoherentDmaBuffer::new(4096, DmaMemoryAttributes::MMIO).expect("allocate coherent DMA");
    let expected_device = buffer.device_addr();

    let mut exported = buffer.into_kernel_api_dma_slice();
    exported.as_slice_mut()[0] = 0x5A;
    exported.as_slice_mut()[4095] = 0xA5;

    let (device_owned, guard) = exported.start_dma();
    assert_eq!(guard.device_address(), expected_device);
    assert_eq!(guard.size(), 4096);

    let cpu_owned = guard.complete(device_owned);
    assert_eq!(cpu_owned.as_slice()[0], 0x5A);
    assert_eq!(cpu_owned.as_slice()[4095], 0xA5);
    drop(cpu_owned);

    assert_eq!(coherent_dma_export_release_count(), 1);
}
