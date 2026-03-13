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
