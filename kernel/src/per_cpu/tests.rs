use super::*;

#[test_case]
fn test_per_cpu_data_layout() {
    // Per-CPUデータがキャッシュラインにアラインされていることを確認
    assert_eq!(core::mem::align_of::<PerCpuData>(), 64);
}

#[test_case]
fn test_per_cpu_hot_layout() {
    // PerCpuHotはキャッシュラインにアラインされていることを確認
    assert_eq!(core::mem::align_of::<PerCpuHot>(), 64);
    // PerCpuHotは1キャッシュライン以内であることを確認
    assert!(core::mem::size_of::<PerCpuHot>() <= 64);
}
