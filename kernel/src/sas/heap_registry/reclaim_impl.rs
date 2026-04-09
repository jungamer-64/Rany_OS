use super::*;

impl HeapRegistry {
    pub fn reclaim_all(&self, domain: DomainId) -> usize {
        // Remove all objects owned by `domain` across all shards, deduplicate
        let mut removed_addrs: BTreeSet<usize> = BTreeSet::new();
        for shard in &self.shards {
            match shard.lock() {
                Ok(mut g) => {
                    let mut to_remove: alloc::vec::Vec<usize> = alloc::vec::Vec::new();
                    for (&addr, obj) in g.objects.iter() {
                        if obj.owner == domain {
                            to_remove.push(addr);
                        }
                    }
                    for addr in to_remove {
                        g.objects.remove(&addr);
                        if let Some(addrs) = g.owner_index.get_mut(&domain) {
                            let addrs: &mut alloc::vec::Vec<usize> = addrs;
                            addrs.retain(|a: &usize| *a != addr);
                        }
                        removed_addrs.insert(addr);
                    }
                }
                Err(_) => {
                    log::error!(
                        "[HEAP] Registry shard lock poisoned (reclaim_all) - skipping shard"
                    );
                }
            }
        }
        let count = removed_addrs.len();
        self.stats
            .total_freed
            .fetch_add(count as u64, Ordering::Relaxed);
        count
    }

    /// Get NUMA node for a shard (optional)
    pub fn shard_node(&self, shard_idx: usize) -> Option<usize> {
        self.shard_nodes.get(shard_idx).copied().unwrap_or(None)
    }

    /// Return shard indices whose affinity equals the owner's NUMA node
    pub fn preferred_shards_for_owner(&self, owner: DomainId) -> alloc::vec::Vec<usize> {
        #[cfg(any(test, feature = "bench"))]
        let _ = owner;

        #[cfg(not(any(test, feature = "bench")))]
        {
            if let Some(node) = crate::domain::get_domain_numa(owner) {
                let mut out = alloc::vec::Vec::new();
                for (i, n) in self.shard_nodes.iter().enumerate() {
                    if let Some(snode) = n {
                        if *snode == node {
                            out.push(i);
                        }
                    }
                }
                return out;
            }
        }

        // If we cannot query domain NUMA info (e.g. lib test build), return empty
        alloc::vec::Vec::new()
    }
}
