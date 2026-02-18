use super::*;


impl PageMemcgTracker {
    pub const fn new() -> Self {
        Self {
            mapping: RwLock::new(BTreeMap::new()),
        }
    }
    
    /// ページを追跡開始
    pub fn track(&self, frame: FrameIndex, memcg_id: MemcgId, charge_type: ChargeType) {
        let mut mapping = self.mapping.write();
        mapping.insert(frame, PageMemcgInfo { memcg_id, charge_type });
    }
    
    /// ページの追跡を解除
    pub fn untrack(&self, frame: FrameIndex) -> Option<PageMemcgInfo> {
        let mut mapping = self.mapping.write();
        mapping.remove(&frame)
    }
    
    /// ページのCgroup情報を取得
    pub fn get(&self, frame: FrameIndex) -> Option<PageMemcgInfo> {
        let mapping = self.mapping.read();
        mapping.get(&frame).copied()
    }
}

pub(crate) static PAGE_MEMCG_TRACKER: PageMemcgTracker = PageMemcgTracker::new();

/// ページをCgroupに関連付け
pub fn memcg_track_page(frame: FrameIndex, memcg_id: MemcgId, charge_type: ChargeType) {
    PAGE_MEMCG_TRACKER.track(frame, memcg_id, charge_type);
}

/// ページのCgroup関連付けを解除
pub fn memcg_untrack_page(frame: FrameIndex) -> Option<PageMemcgInfo> {
    PAGE_MEMCG_TRACKER.untrack(frame)
}

/// ページのMemcg追跡を解除し、カウンタをアンチャージする
///
/// `memcg_untrack_page` + `memcg_uncharge` の一括ヘルパー。
/// 複数ファイルに分散していた共通パターンを統合。
pub fn memcg_untrack_and_uncharge(frame: FrameIndex, pages: u64) {
    if let Some(info) = memcg_untrack_page(frame) {
        memcg_uncharge(info.memcg_id, pages, info.charge_type);
    }
}

/// ページのCgroup情報を取得
pub fn memcg_get_page_info(frame: FrameIndex) -> Option<PageMemcgInfo> {
    PAGE_MEMCG_TRACKER.get(frame)
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

