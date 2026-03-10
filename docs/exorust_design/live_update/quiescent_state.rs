//! Quiescent State Detection
//!
//! 設計書セクション 3.5.3 参照

use core::sync::atomic::Ordering::Acquire;

/// Quiescent Stateの検出
///
/// 全Executorが「安全な状態」に到達したことを検出する
pub fn wait_for_quiescent_state(old_epoch: u64) {
    loop {
        let all_departed = (0..num_cpus()).all(|cpu| {
            let core_epoch = PER_CORE_EPOCHS[cpu].local_epoch.load(Acquire);
            let in_cs = PER_CORE_EPOCHS[cpu].in_critical_section.load(Acquire);

            // コアがクリティカルセクション外か、新エポックに移行済み
            !in_cs || core_epoch > old_epoch
        });

        if all_departed {
            break;
        }

        // 短いスピンウェイト後、Executorにyieldを促す
        core::hint::spin_loop();
    }
}

// 以下は型定義のプレースホルダー
use super::epoch_management::PerCoreEpoch;

static PER_CORE_EPOCHS: [PerCoreEpoch; 64] = {
    const INIT: PerCoreEpoch = PerCoreEpoch::new();
    [INIT; 64]
};

fn num_cpus() -> usize {
    1 // プレースホルダー
}
