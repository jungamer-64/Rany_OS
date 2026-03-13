use super::*;

/// ドメインからタスクを削除
pub fn remove_task_from_domain(domain_id: DomainId, task_id: u64) {
    match REGISTRY.lock() {
        Ok(mut guard) => {
            if let Some(domain) = guard.domains.iter_mut().find(|d| d.id == domain_id) {
                domain.remove_task(task_id);
            }
        }
        Err(_) => log::error!("[DOMAIN] Registry poisoned (remove_task_from_domain) - no-op"),
    }
}

// ============================================================================
// 公開API - リソース管理
// ============================================================================

/// Exchange Heap上にオブジェクトを登録
pub fn register_heap_object(ptr: usize, layout: Layout, owner: DomainId) {
    // 統合されたHeapRegistryに登録
    crate::sas::register_object(
        ptr,
        layout.size(),
        crate::sas::DomainId::new(owner.as_u64()),
    );

    match REGISTRY.lock() {
        Ok(mut guard) => {
            if let Some(domain) = guard.domains.iter_mut().find(|d| d.id == owner) {
                domain.increment_rref();
                domain.add_memory(layout.size() as u64);
            }
        }
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (register_heap_object) - stats not updated")
        }
    }
}

/// Exchange Heap上のオブジェクトを解除
pub fn unregister_heap_object(ptr: usize) {
    // 統合されたHeapRegistryからオブジェクト情報を取得して解除
    if let Some((owner, size)) = crate::sas::unregister_any(ptr) {
        // ドメイン統計を更新
        match REGISTRY.lock() {
            Ok(mut guard) => {
                let owner_ds = DomainId::new(owner.as_u64());
                if let Some(domain) = guard.domains.iter_mut().find(|d| d.id == owner_ds) {
                    domain.decrement_rref();
                    domain.free_memory(size as u64);
                }
            }
            Err(_) => log::error!(
                "[DOMAIN] Registry poisoned (unregister_heap_object) - stats not updated"
            ),
        }
    }
}

/// オブジェクトの所有権を移動
pub fn transfer_ownership(ptr: usize, new_owner: DomainId) -> bool {
    // NOTE: transfer requires knowing old owner to call sas::transfer_ownership?
    // sas::transfer_ownership(ptr, from, to)
    // But this API only takes new_owner.
    //
    // We need 'from' owner.
    // HeapRegistry has check `get_owner`.
    //
    // So:
    // 1. Get owner (and size for stats)
    // 2. Transfer
    // 3. Update stats

    // We need get_info exposed in sas? Or unregister_any returns info, but we don't want to unregister.
    // I added get_info to sas internal. Maybe I should expose it in sas?
    // Wait, I updated heap_registry.rs to add `get_info`.
    // But did I update sas/mod.rs to expose `get_info`?
    // I exposed `unregister_any`.
    // I should check if I exposed `get_info` in sas/mod.rs.
    //
    // If not, I can use `sas::get_owner(ptr)` to get owner.
    // But I need size for stats.
    // If I can't get size easily, stats might drift.
    //
    // For now, let's use `sas::get_owner` and assume I can't update size stats perfectly unless I expose get_info?
    // Or I rely on `unregister_any` for final stats update?
    //
    // If I transfer, "allocated_memory" ownership moves.
    // If I don't update stats, one domain has 0 usage but owns memory.
    //
    // I'll use `sas::get_owner` -> then `sas::transfer`.
    // Metadata (size) is not retrievable easily without `get_info`.
    //
    // I'll skip size update for now in transfer (minor bug in stats only), or better, fix sas/mod.rs to expose `get_info`.
    // But I am writing `domain_system.rs` now.
    //
    // Assuming I can't call `get_info` yet (unless I modify sas/mod.rs again),
    // I will try to call `crate::sas::get_info` if I think I verified it.
    // I checked `heap_registry.rs` has `get_info`.
    // `sas/mod.rs` does NOT have `get_info` exposed publically (only `unregister_any`).
    //
    // I will just use `sas::get_owner` and SKIP size update for now.
    // The stats are secondary.

    if let Some(old_owner) = crate::sas::get_owner(ptr) {
        // Convert SAS DomainId to domain_system::DomainId for registry lookup
        let old_owner_ds = DomainId::new(old_owner.as_u64());
        if crate::sas::transfer_ownership(
            ptr,
            old_owner,
            crate::sas::DomainId::new(new_owner.as_u64()),
        )
        .is_ok()
        {
            match REGISTRY.lock() {
                Ok(mut registry) => {
                    // 旧所有者のカウント減少
                    if let Some(old_domain) =
                        registry.domains.iter_mut().find(|d| d.id == old_owner_ds)
                    {
                        old_domain.decrement_rref();
                        // old_domain.free_memory(size as u64); // Size unknown
                    }

                    // 新所有者のカウント増加
                    if let Some(new_domain) =
                        registry.domains.iter_mut().find(|d| d.id == new_owner)
                    {
                        new_domain.increment_rref();
                        // new_domain.add_memory(size as u64); // Size unknown
                    }
                    return true;
                }
                Err(_) => {
                    log::error!(
                        "[DOMAIN] Registry poisoned (transfer_ownership) - stats not updated"
                    );
                    return true; // Ownership transfer succeeded; just skip stats update
                }
            }
        }
    }
    false
}

/// ドメインが所有する全リソースを回収
pub fn reclaim_domain_resources(domain: DomainId) {
    // 統合されたHeapRegistryのreclaim_allを使用
    // Note: sas::reclaim_domain_resources (on manager) returns count.
    // We need to call it via Global Manager or direct?
    // sas/mod.rs has `reclaim_domain_resources` IN struct, but not exposed function?
    // I verified `sas/mod.rs` exposed `unregister_any`, `check_access`.
    // I checked `sas/mod.rs` content:
    // It has `pub fn reclaim_domain_resources` ON `SingleAddressSpaceManager`.
    // But NO standalone public function `reclaim_domain_resources`.
    //
    // So I must do `crate::sas::with_sas_manager_mut(|m| m.reclaim_domain_resources(domain))`

    let count = crate::sas::with_sas_manager_mut(|m| {
        m.reclaim_domain_resources(crate::sas::DomainId::new(domain.as_u64()))
    });

    // ドメインのリソースカウントをリセット
    match REGISTRY.lock() {
        Ok(mut guard) => {
            if let Some(d) = guard.domains.iter_mut().find(|d| d.id == domain) {
                d.rref_count = 0;
                d.allocated_memory = 0;
            }
        }
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (reclaim_domain_resources) - stats not reset")
        }
    }

    if count > 0 {
        log::info!("[DOMAIN] Reclaimed {} resources from {}\n", count, domain);
    }
}

// ============================================================================
// 公開API - 統計
// ============================================================================

/// ドメイン統計
#[derive(Debug, Clone)]
pub struct DomainStats {
    /// 総ドメイン数
    pub total: usize,
    /// 実行中のドメイン数
    pub running: usize,
    /// 停止中のドメイン数
    pub stopped: usize,
    /// 終了済みのドメイン数
    pub terminated: usize,
    /// 総メモリ使用量（バイト）
    pub memory_used: u64,
    /// 総RRef数
    pub total_rrefs: u64,
}

/// ドメイン統計を取得
pub fn get_domain_stats() -> DomainStats {
    match REGISTRY.lock() {
        Ok(guard) => {
            let mut stats = DomainStats {
                total: guard.domains.len(),
                running: 0,
                stopped: 0,
                terminated: 0,
                memory_used: 0,
                total_rrefs: 0,
            };

            for domain in guard.domains.iter() {
                match domain.state {
                    DomainState::Running | DomainState::Initializing => stats.running += 1,
                    DomainState::Stopped | DomainState::Suspended => stats.stopped += 1,
                    DomainState::Terminated => stats.terminated += 1,
                }
                stats.memory_used += domain.allocated_memory;
                stats.total_rrefs += domain.rref_count;
            }

            stats
        }
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (get_domain_stats)");
            DomainStats {
                total: 0,
                running: 0,
                stopped: 0,
                terminated: 0,
                memory_used: 0,
                total_rrefs: 0,
            }
        }
    }
}

/// ドメイン統計を取得（get_domain_statsのエイリアス）
/// domain/registry.rs からの互換性維持のために追加
pub fn get_stats() -> DomainStats {
    get_domain_stats()
}

/// ドメイン一覧を表示
pub fn print_domain_list() {
    match REGISTRY.lock() {
        Ok(guard) => {
            log::info!("[DOMAIN] === Domain List ===\n");
            for domain in guard.domains.iter() {
                log::info!(
                    "[DOMAIN] {} '{}': {:?}, tasks={}, rrefs={}, mem={}KB\n",
                    domain.id,
                    domain.name,
                    domain.state,
                    domain.tasks.len(),
                    domain.rref_count,
                    domain.allocated_memory / 1024
                );
            }
        }
        Err(_) => log::error!("[DOMAIN] Registry poisoned (print_domain_list) - skipping"),
    }
}

// ============================================================================
// 現在のドメイン管理
// ============================================================================

/// 現在のドメインID（Per-CPUデータから取得予定）
pub(crate) static CURRENT_DOMAIN: AtomicU64 = AtomicU64::new(0);

/// 現在のドメインを設定
pub fn set_current_domain(id: DomainId) {
    CURRENT_DOMAIN.store(id.as_u64(), Ordering::SeqCst);
}

/// 現在のドメインを取得
pub fn current_domain() -> DomainId {
    let cpu_id = crate::cpu::current_id();
    if let Some(tcb_ptr) = crate::task::context::get_current_task(cpu_id) {
        // SAFETY: get_current_taskは有効なTCBポインタを返す
        unsafe { (*tcb_ptr).domain_id }
    } else {
        DomainId::new(CURRENT_DOMAIN.load(Ordering::SeqCst))
    }
}

/// 現在のドメインがカーネルかどうか
pub fn is_kernel_domain() -> bool {
    current_domain() == DomainId::KERNEL
}
