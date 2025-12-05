// ============================================================================
// src/graphics/compositor/dirty_rect.rs - Dirty Rectangle Management
// ============================================================================

//! ダーティ矩形管理

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::graphics::Rect;
use super::constants::MAX_DIRTY_RECTS;

// ============================================================================
// Dirty Rectangle
// ============================================================================

/// ダーティ矩形（再描画が必要な領域）
#[derive(Clone, Copy, Debug)]
pub struct DirtyRect {
    pub rect: Rect,
    /// 優先度（高いほど先に処理）
    pub priority: u8,
}

impl DirtyRect {
    pub fn new(rect: Rect) -> Self {
        Self { rect, priority: 0 }
    }

    pub fn with_priority(rect: Rect, priority: u8) -> Self {
        Self { rect, priority }
    }
}

/// ダーティリージョンマネージャ
pub struct DirtyRegionManager {
    /// ダーティ矩形リスト
    regions: Vec<DirtyRect>,
    /// 画面サイズ
    screen_width: u32,
    screen_height: u32,
    /// 全画面再描画フラグ
    full_redraw: bool,
}

impl DirtyRegionManager {
    pub fn new(screen_width: u32, screen_height: u32) -> Self {
        Self {
            regions: Vec::with_capacity(MAX_DIRTY_RECTS),
            screen_width,
            screen_height,
            full_redraw: true, // 初回は全画面再描画
        }
    }

    /// ダーティ矩形を追加
    pub fn add_dirty(&mut self, rect: Rect) {
        if self.full_redraw {
            return;
        }

        // 画面外は無視
        let screen_rect = Rect::new(0, 0, self.screen_width, self.screen_height);
        let Some(clipped) = rect.intersection(&screen_rect) else {
            return;
        };

        // 既存の矩形とマージを試みる
        for region in &mut self.regions {
            if let Some(merged) = try_merge_rects(&region.rect, &clipped) {
                region.rect = merged;
                return;
            }
        }

        // 新規追加
        if self.regions.len() < MAX_DIRTY_RECTS {
            self.regions.push(DirtyRect::new(clipped));
        } else {
            // 上限を超えたら全画面再描画
            self.full_redraw = true;
        }
    }

    /// 全画面を無効化
    pub fn invalidate_all(&mut self) {
        self.full_redraw = true;
        self.regions.clear();
    }

    /// ダーティ領域をクリア
    pub fn clear(&mut self) {
        self.regions.clear();
        self.full_redraw = false;
    }

    /// 全画面再描画が必要か
    pub fn needs_full_redraw(&self) -> bool {
        self.full_redraw
    }

    /// ダーティ領域を取得
    pub fn get_dirty_regions(&self) -> &[DirtyRect] {
        &self.regions
    }

    /// 指定矩形と交差するダーティ領域があるか
    #[allow(dead_code)]
    pub fn intersects(&self, rect: &Rect) -> bool {
        if self.full_redraw {
            return true;
        }
        self.regions.iter().any(|r| r.rect.intersects(rect))
    }

    /// ダーティ領域を最適化（重複を統合）
    pub fn optimize(&mut self) {
        if self.full_redraw || self.regions.len() <= 1 {
            return;
        }

        let mut optimized = Vec::with_capacity(self.regions.len());
        let mut used = vec![false; self.regions.len()];

        for i in 0..self.regions.len() {
            if used[i] {
                continue;
            }

            let mut current = self.regions[i].rect;
            used[i] = true;

            // 他の矩形とマージを試みる
            loop {
                let mut merged = false;
                for j in 0..self.regions.len() {
                    if used[j] {
                        continue;
                    }

                    if let Some(m) = try_merge_rects(&current, &self.regions[j].rect) {
                        current = m;
                        used[j] = true;
                        merged = true;
                    }
                }

                if !merged {
                    break;
                }
            }

            optimized.push(DirtyRect::new(current));
        }

        self.regions = optimized;
    }
}

/// 2つの矩形をマージ（近い場合のみ）
fn try_merge_rects(a: &Rect, b: &Rect) -> Option<Rect> {
    // 交差または隣接している場合はマージ
    let gap = 16; // マージ許容ギャップ

    let a_right = a.x + a.width as i32;
    let a_bottom = a.y + a.height as i32;
    let b_right = b.x + b.width as i32;
    let b_bottom = b.y + b.height as i32;

    // 隣接チェック（ギャップを考慮）
    if a_right + gap < b.x || b_right + gap < a.x {
        return None;
    }
    if a_bottom + gap < b.y || b_bottom + gap < a.y {
        return None;
    }

    // マージした矩形を計算
    let x = a.x.min(b.x);
    let y = a.y.min(b.y);
    let right = a_right.max(b_right);
    let bottom = a_bottom.max(b_bottom);

    // マージ後のサイズが妥当かチェック（無駄な領域が増えすぎないように）
    let merged_area = (right - x) * (bottom - y);
    let original_area = (a.width * a.height + b.width * b.height) as i32;

    if merged_area <= original_area * 2 {
        Some(Rect::new(x, y, (right - x) as u32, (bottom - y) as u32))
    } else {
        None
    }
}
