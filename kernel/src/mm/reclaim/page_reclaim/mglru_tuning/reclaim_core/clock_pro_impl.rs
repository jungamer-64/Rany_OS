use super::*;


impl ClockProList {
    pub const fn new() -> Self {
        Self {
            pages: spin::Mutex::new(VecDeque::new()),
            hand_cold: AtomicUsize::new(0),
            hand_hot: AtomicUsize::new(0),
            hand_test: AtomicUsize::new(0),
            cold_count: AtomicUsize::new(0),
            hot_count: AtomicUsize::new(0),
            test_count: AtomicUsize::new(0),
            target_cold: AtomicUsize::new(0),
            cold_evictions: AtomicU64::new(0),
            hot_demotions: AtomicU64::new(0),
            test_promotions: AtomicU64::new(0),
            target_adjustments: AtomicU64::new(0),
        }
    }

    /// 新しいページを追加（常にColdとして開始）
    pub fn add_page(&self, frame: FrameIndex, timestamp: u64) {
        let entry = ClockProEntry::new(frame, ClockProState::Cold, timestamp);
        
        let mut pages = self.pages.lock();
        pages.push_back(entry);
        self.cold_count.fetch_add(1, Ordering::Relaxed);
    }

    /// ページアクセスを記録
    pub fn access_page(&self, frame: FrameIndex) {
        let pages = self.pages.lock();
        
        for entry in pages.iter() {
            if entry.frame == frame {
                entry.set_referenced();
                break;
            }
        }
    }

    /// Hand Coldを進めて非参照Coldページを回収
    /// 
    /// # Returns
    /// 回収するフレームのリスト
    /// Coldエントリを回収試行し、成功時はTestエントリに変換する
    pub(super) fn try_evict_cold_entry(
        &self,
        pages: &mut alloc::collections::VecDeque<ClockProEntry>,
        hand: usize,
    ) -> Option<FrameIndex> {
        let entry = pages.get(hand)?;
        if entry.test_clear_referenced() {
            return None; // 参照あり → Hotに昇格予定
        }
        let frame = entry.frame;
        if let Some(mut removed) = pages.remove(hand) {
            removed.state = ClockProState::Test;
            pages.push_back(removed);
            self.cold_count.fetch_sub(1, Ordering::Relaxed);
            self.test_count.fetch_add(1, Ordering::Relaxed);
        }
        self.cold_evictions.fetch_add(1, Ordering::Relaxed);
        Some(frame)
    }

    pub fn run_hand_cold(&self, target_count: usize) -> Vec<FrameIndex> {
        let mut pages = self.pages.lock();
        let mut victims = Vec::new();
        
        if pages.is_empty() {
            return victims;
        }
        
        let mut hand = self.hand_cold.load(Ordering::Relaxed) % pages.len().max(1);
        let mut scanned = 0;
        let max_scan = pages.len() * 2; // 最大2周
        
        while victims.len() < target_count && scanned < max_scan {
            if pages.is_empty() {
                break;
            }
            
            hand = hand % pages.len();
            
            if let Some(entry) = pages.get(hand) {
                match entry.state {
                    ClockProState::Cold => {
                        if let Some(frame) = self.try_evict_cold_entry(&mut pages, hand) {
                            victims.push(frame);
                            continue; // handは同じ位置で次の要素を見る
                        }
                    }
                    ClockProState::Hot => {
                        // Hand Coldはスキップ
                    }
                    ClockProState::Test => {
                        // Test: 期限切れなら削除
                    }
                }
            }
            
            hand = (hand + 1) % pages.len().max(1);
            scanned += 1;
        }
        
        self.hand_cold.store(hand, Ordering::Relaxed);
        victims
    }

    /// Hand Hotを進めて非参照Hotページを降格
    pub fn run_hand_hot(&self, scan_count: usize) -> usize {
        let mut pages = self.pages.lock();
        
        if pages.is_empty() {
            return 0;
        }
        
        let mut hand = self.hand_hot.load(Ordering::Relaxed) % pages.len().max(1);
        let mut demoted = 0;
        
        for _ in 0..scan_count {
            if pages.is_empty() {
                break;
            }
            
            hand = hand % pages.len();
            
            if let Some(entry) = pages.get_mut(hand) {
                if entry.state == ClockProState::Hot {
                    if entry.test_clear_referenced() {
                        // 参照あり → そのまま維持
                    } else {
                        // 参照なし → Coldに降格
                        entry.state = ClockProState::Cold;
                        self.hot_count.fetch_sub(1, Ordering::Relaxed);
                        self.cold_count.fetch_add(1, Ordering::Relaxed);
                        self.hot_demotions.fetch_add(1, Ordering::Relaxed);
                        demoted += 1;
                    }
                }
            }
            
            hand = (hand + 1) % pages.len().max(1);
        }
        
        self.hand_hot.store(hand, Ordering::Relaxed);
        demoted
    }

    /// Testエントリにヒットした場合の処理
    /// 
    /// Testにあるページが再度アクセスされた場合、
    /// そのページはワーキングセットの一部とみなしてHotに昇格する。
    /// また、ターゲットCold数を増加させる。
    pub fn handle_test_hit(&self, frame: FrameIndex) -> bool {
        let mut pages = self.pages.lock();
        
        for entry in pages.iter_mut() {
            if entry.frame == frame && entry.state == ClockProState::Test {
                // Test → Hot昇格
                entry.state = ClockProState::Hot;
                entry.promoted_from_test = true;
                
                self.test_count.fetch_sub(1, Ordering::Relaxed);
                self.hot_count.fetch_add(1, Ordering::Relaxed);
                self.test_promotions.fetch_add(1, Ordering::Relaxed);
                
                // ターゲットCold数を増加（ワーキングセット拡大の兆候）
                let old_target = self.target_cold.fetch_add(1, Ordering::Relaxed);
                if old_target < 1000 { // 上限
                    self.target_adjustments.fetch_add(1, Ordering::Relaxed);
                }
                
                return true;
            }
        }
        
        false
    }

    /// 統計情報を取得
    pub fn stats(&self) -> ClockProStats {
        ClockProStats {
            cold_pages: self.cold_count.load(Ordering::Relaxed),
            hot_pages: self.hot_count.load(Ordering::Relaxed),
            test_pages: self.test_count.load(Ordering::Relaxed),
            target_cold: self.target_cold.load(Ordering::Relaxed),
            cold_evictions: self.cold_evictions.load(Ordering::Relaxed),
            hot_demotions: self.hot_demotions.load(Ordering::Relaxed),
            test_promotions: self.test_promotions.load(Ordering::Relaxed),
        }
    }

    /// リストのサイズ
    pub fn len(&self) -> usize {
        let pages = self.pages.lock();
        pages.len()
    }

    /// リストが空かどうか
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
