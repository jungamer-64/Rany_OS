use super::*;

#[test_case]
fn test_per_cpu_hot_layout() {
    // PerCpuHotはキャッシュラインにアラインされていることを確認
    assert_eq!(core::mem::align_of::<PerCpuHot>(), 64);
    // PerCpuHotは1キャッシュライン以内であることを確認
    assert!(core::mem::size_of::<PerCpuHot>() <= 64);
}

#[test_case]
fn test_per_cpu_hot_and_cold_linkage() {
    let hot = hot_for_cpu(0).expect("cpu0 hot state missing");
    let cold = cold_for_cpu(0).expect("cpu0 cold state missing");

    assert_eq!(hot.cpu_id, 0);
    assert_eq!(hot.cold().get_local_numa_node(), cold.get_local_numa_node());
}
