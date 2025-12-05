// ============================================================================
// src/application/system_monitor.rs - System Monitor GUI Application
// ============================================================================
//!
//! # System Monitor (Task Manager)
//!
//! CompositorWindow を使用したGUIアプリケーションとして、
//! システムリソースをリアルタイムで監視するタスクマネージャー
//!
//! ## 機能
//! - CPU使用率グラフ: 過去60秒間の折れ線グラフ
//! - メモリ使用量バー: ヒープ・物理メモリの進捗バー
//! - プロセスリスト: タスクID、状態、CPU時間、クリックでkill
//! - 更新頻度: タイマーイベント（ダーティ矩形を意識）

#![allow(dead_code)]
#![allow(unused_variables)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::graphics::{Color, image::Image, Rect};
use crate::monitor::{self, SystemSnapshot};
use crate::task::{process_manager, ProcessId, ProcessState, current_tick};

// ============================================================================
// Constants
// ============================================================================

/// ウィンドウの幅
const WINDOW_WIDTH: u32 = 640;
/// ウィンドウの高さ
const WINDOW_HEIGHT: u32 = 480;

/// CPU履歴のサンプル数 (60秒分)
const CPU_HISTORY_SIZE: usize = 60;

/// 更新間隔 (ミリ秒)
const REFRESH_INTERVAL_MS: u64 = 1000;

/// グラフの色
const COLOR_BACKGROUND: Color = Color::new(245, 245, 245);
const COLOR_GRAPH_BG: Color = Color::new(255, 255, 255);
const COLOR_GRAPH_BORDER: Color = Color::new(200, 200, 200);
const COLOR_GRAPH_LINE: Color = Color::new(0, 120, 215);
const COLOR_GRAPH_FILL: Color = Color::with_alpha(0, 120, 215, 64);
const COLOR_GRAPH_GRID: Color = Color::new(230, 230, 230);
const COLOR_MEMORY_USED: Color = Color::new(139, 195, 74);
const COLOR_MEMORY_FREE: Color = Color::new(224, 224, 224);
const COLOR_TEXT: Color = Color::BLACK;
const COLOR_HEADER: Color = Color::new(33, 33, 33);
const COLOR_ROW_ALT: Color = Color::new(250, 250, 250);
const COLOR_ROW_SELECTED: Color = Color::new(200, 230, 255);
const COLOR_KILL_BUTTON: Color = Color::new(244, 67, 54);
const COLOR_KILL_TEXT: Color = Color::WHITE;

// ============================================================================
// SystemMonitor
// ============================================================================

/// システムモニター (タスクマネージャー)
pub struct SystemMonitor {
    /// CPU使用率履歴 (0-100)
    cpu_history: [u8; CPU_HISTORY_SIZE],
    /// 履歴のヘッドインデックス (リングバッファ)
    history_head: usize,
    /// 最新のシステムスナップショット
    last_snapshot: Option<SystemSnapshot>,
    /// プロセス一覧 (キャッシュ)
    process_list: Vec<ProcessEntry>,
    /// 選択されたプロセスのインデックス
    selected_process: Option<usize>,
    /// スクロールオフセット
    scroll_offset: usize,
    /// 最終更新時のタイマーtick
    last_update_tick: u64,
    /// ダーティフラグ - CPU グラフ領域
    dirty_cpu_graph: bool,
    /// ダーティフラグ - メモリバー領域
    dirty_memory_bar: bool,
    /// ダーティフラグ - プロセスリスト領域
    dirty_process_list: bool,
    /// 実行中フラグ
    running: AtomicBool,
}

/// プロセスエントリ
#[derive(Clone)]
pub struct ProcessEntry {
    /// プロセスID
    pub pid: ProcessId,
    /// プロセス名
    pub name: String,
    /// 状態
    pub state: ProcessState,
    /// CPU時間 (ms)
    pub cpu_time_ms: u64,
    /// メモリ使用量 (bytes)
    pub memory_bytes: usize,
}

impl ProcessEntry {
    /// 状態を文字列に変換
    pub fn state_str(&self) -> &'static str {
        match self.state {
            ProcessState::Creating => "Creating",
            ProcessState::Ready => "Ready",
            ProcessState::Running => "Running",
            ProcessState::Blocked => "Blocked",
            ProcessState::Stopped => "Stopped",
            ProcessState::Zombie => "Zombie",
            ProcessState::Dead => "Dead",
        }
    }
}

impl Default for SystemMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemMonitor {
    /// 新しいシステムモニターを作成
    pub fn new() -> Self {
        Self {
            cpu_history: [0; CPU_HISTORY_SIZE],
            history_head: 0,
            last_snapshot: None,
            process_list: Vec::new(),
            selected_process: None,
            scroll_offset: 0,
            last_update_tick: 0,
            dirty_cpu_graph: true,
            dirty_memory_bar: true,
            dirty_process_list: true,
            running: AtomicBool::new(true),
        }
    }

    /// モニタリングを開始
    pub fn start(&self) {
        self.running.store(true, Ordering::SeqCst);
    }

    /// モニタリングを停止
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// 実行中かどうか
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// 更新が必要かどうかをチェック (タイマーベース)
    pub fn needs_update(&self) -> bool {
        if !self.is_running() {
            return false;
        }
        let now = current_tick();
        now.saturating_sub(self.last_update_tick) >= REFRESH_INTERVAL_MS
    }

    /// システム情報を更新
    pub fn update(&mut self) {
        if !self.is_running() {
            return;
        }

        let now = current_tick();
        self.last_update_tick = now;

        // システムスナップショットを取得
        let snapshot = monitor::snapshot();

        // CPU履歴を更新 (リングバッファ)
        self.cpu_history[self.history_head] = snapshot.cpu_usage;
        self.history_head = (self.history_head + 1) % CPU_HISTORY_SIZE;

        // プロセス一覧を更新
        self.update_process_list();

        // スナップショットを保存
        self.last_snapshot = Some(snapshot);

        // 全領域をダーティに
        self.dirty_cpu_graph = true;
        self.dirty_memory_bar = true;
        self.dirty_process_list = true;
    }

    /// プロセス一覧を更新
    fn update_process_list(&mut self) {
        let manager = process_manager();
        let pids = manager.list();

        self.process_list.clear();

        for pid in pids {
            if let Some(info_lock) = manager.get(pid) {
                let info = info_lock.read();
                self.process_list.push(ProcessEntry {
                    pid,
                    name: info.name.clone(),
                    state: info.state,
                    cpu_time_ms: info.stats.user_time.load(Ordering::Relaxed)
                        + info.stats.system_time.load(Ordering::Relaxed),
                    memory_bytes: 0, // TODO: プロセスごとのメモリ使用量
                });
            }
        }

        // PIDでソート
        self.process_list.sort_by_key(|e| e.pid);
    }

    /// プロセスを選択
    pub fn select_process(&mut self, index: usize) {
        if index < self.process_list.len() {
            self.selected_process = Some(index);
            self.dirty_process_list = true;
        }
    }

    /// 選択されたプロセスを強制終了
    pub fn kill_selected_process(&mut self) -> Result<(), &'static str> {
        if let Some(index) = self.selected_process {
            if let Some(entry) = self.process_list.get(index) {
                let pid = entry.pid;
                // SIGKILL を送信
                use crate::task::signal::{Signal, kill, TaskId as SignalTaskId};
                
                let task_id = SignalTaskId::new(pid.as_u64());
                kill(task_id, Signal::SIGKILL).map_err(|_| "Failed to kill process")?;
                
                // リストを更新
                self.selected_process = None;
                self.dirty_process_list = true;
                return Ok(());
            }
        }
        Err("No process selected")
    }

    /// スクロールアップ
    pub fn scroll_up(&mut self) {
        if self.scroll_offset > 0 {
            self.scroll_offset -= 1;
            self.dirty_process_list = true;
        }
    }

    /// スクロールダウン
    pub fn scroll_down(&mut self) {
        let max_visible = self.max_visible_processes();
        if self.scroll_offset + max_visible < self.process_list.len() {
            self.scroll_offset += 1;
            self.dirty_process_list = true;
        }
    }

    /// 表示可能なプロセス数
    fn max_visible_processes(&self) -> usize {
        10 // プロセスリスト領域に表示できる行数
    }

    /// Y座標からプロセスインデックスを取得
    pub fn process_at_y(&self, y: i32, list_start_y: i32) -> Option<usize> {
        let row_height = 20;
        let relative_y = y - list_start_y;
        if relative_y < 0 {
            return None;
        }
        let row = (relative_y as usize) / row_height;
        let index = self.scroll_offset + row;
        if index < self.process_list.len() {
            Some(index)
        } else {
            None
        }
    }

    // ========================================================================
    // Rendering
    // ========================================================================

    /// コンテンツをバッファに描画
    pub fn render(&mut self, buffer: &mut Image) {
        // 背景をクリア
        let full_rect = Rect::new(0, 0, buffer.width(), buffer.height());
        buffer.fill_rect(full_rect, COLOR_BACKGROUND);

        // 各セクションを描画
        self.render_header(buffer);
        self.render_cpu_graph(buffer);
        self.render_memory_bars(buffer);
        self.render_process_list(buffer);

        // ダーティフラグをクリア
        self.dirty_cpu_graph = false;
        self.dirty_memory_bar = false;
        self.dirty_process_list = false;
    }

    /// ダーティ領域のみを再描画
    pub fn render_dirty(&mut self, buffer: &mut Image) -> Vec<Rect> {
        let mut dirty_rects = Vec::new();

        if self.dirty_cpu_graph {
            self.render_cpu_graph(buffer);
            dirty_rects.push(self.cpu_graph_rect());
            self.dirty_cpu_graph = false;
        }

        if self.dirty_memory_bar {
            self.render_memory_bars(buffer);
            dirty_rects.push(self.memory_bar_rect());
            self.dirty_memory_bar = false;
        }

        if self.dirty_process_list {
            self.render_process_list(buffer);
            dirty_rects.push(self.process_list_rect());
            self.dirty_process_list = false;
        }

        dirty_rects
    }

    /// ヘッダーを描画
    fn render_header(&self, buffer: &mut Image) {
        // タイトル
        let title = "System Monitor";
        draw_text(buffer, 10, 5, title, COLOR_HEADER, 2);

        // 更新時刻
        if let Some(ref snap) = self.last_snapshot {
            let tick_str = format!("Tick: {}", snap.timestamp);
            draw_text(buffer, 500, 10, &tick_str, COLOR_TEXT, 1);
        }
    }

    /// CPUグラフ領域
    fn cpu_graph_rect(&self) -> Rect {
        Rect::new(10, 40, WINDOW_WIDTH - 20, 120)
    }

    /// CPU使用率グラフを描画
    fn render_cpu_graph(&self, buffer: &mut Image) {
        let rect = self.cpu_graph_rect();
        let x = rect.x;
        let y = rect.y;
        let w = rect.width;
        let h = rect.height;

        // 背景
        buffer.fill_rect(rect, COLOR_GRAPH_BG);

        // グリッド線 (25%, 50%, 75%)
        for percent in [25u32, 50, 75] {
            let grid_y = y + (h as i32 * (100 - percent as i32) / 100);
            for gx in (x..(x + w as i32)).step_by(4) {
                if gx >= 0 && grid_y >= 0 {
                    buffer.set_pixel(gx as u32, grid_y as u32, COLOR_GRAPH_GRID);
                }
            }
        }

        // ラベル
        draw_text(buffer, x + 2, y + 2, "CPU %", COLOR_TEXT, 1);
        draw_text(buffer, x + 2, y + h as i32 - 12, "0%", COLOR_TEXT, 1);
        draw_text(buffer, x + 2, y + h as i32 / 2 - 6, "50%", COLOR_TEXT, 1);
        draw_text(buffer, x + w as i32 - 35, y + 2, "100%", COLOR_TEXT, 1);

        // グラフエリア (ラベル分のマージン)
        let graph_x = x + 40;
        let graph_w = w - 50;
        let graph_h = h - 10;

        // データポイントを描画 (折れ線グラフ)
        let mut prev_point: Option<(i32, i32)> = None;
        let sample_width = graph_w as f32 / CPU_HISTORY_SIZE as f32;

        for i in 0..CPU_HISTORY_SIZE {
            let idx = (self.history_head + i) % CPU_HISTORY_SIZE;
            let value = self.cpu_history[idx];

            let px = graph_x + (i as f32 * sample_width) as i32;
            let py = y + 5 + ((graph_h as i32 * (100 - value as i32)) / 100);

            // 塗りつぶし
            for fill_y in py..(y + h as i32 - 5) {
                if px >= 0 && fill_y >= 0 {
                    buffer.set_pixel(px as u32, fill_y as u32, COLOR_GRAPH_FILL);
                }
            }

            // 線を描画
            if let Some((prev_x, prev_y)) = prev_point {
                draw_line(buffer, prev_x, prev_y, px, py, COLOR_GRAPH_LINE);
            }
            prev_point = Some((px, py));
        }

        // 枠
        draw_rect_outline(buffer, rect, COLOR_GRAPH_BORDER);

        // 現在の値を表示
        if let Some(ref snap) = self.last_snapshot {
            let cpu_str = format!("{}%", snap.cpu_usage);
            draw_text(buffer, x + w as i32 - 50, y + h as i32 - 20, &cpu_str, COLOR_GRAPH_LINE, 2);
        }
    }

    /// メモリバー領域
    fn memory_bar_rect(&self) -> Rect {
        Rect::new(10, 170, WINDOW_WIDTH - 20, 60)
    }

    /// メモリ使用量バーを描画
    fn render_memory_bars(&self, buffer: &mut Image) {
        let rect = self.memory_bar_rect();
        let x = rect.x;
        let y = rect.y;
        let w = rect.width;

        // ラベル
        draw_text(buffer, x, y, "Memory", COLOR_HEADER, 1);

        if let Some(ref snap) = self.last_snapshot {
            let mem = &snap.memory;

            // ヒープメモリバー
            let bar_x = x + 80;
            let bar_y = y + 5;
            let bar_w = w - 90;
            let bar_h = 20u32;

            // 背景
            buffer.fill_rect(Rect::new(bar_x, bar_y, bar_w, bar_h), COLOR_MEMORY_FREE);

            // 使用量
            let used_w = if mem.heap_total > 0 {
                ((bar_w as usize * mem.heap_used) / mem.heap_total) as u32
            } else {
                0
            };
            if used_w > 0 {
                buffer.fill_rect(Rect::new(bar_x, bar_y, used_w, bar_h), COLOR_MEMORY_USED);
            }

            // 枠
            draw_rect_outline(buffer, Rect::new(bar_x, bar_y, bar_w, bar_h), COLOR_GRAPH_BORDER);

            // 数値
            let mem_str = format!(
                "{} / {} ({}%)",
                format_bytes(mem.heap_used),
                format_bytes(mem.heap_total),
                mem.usage_percent
            );
            draw_text(buffer, bar_x + 5, bar_y + 4, &mem_str, COLOR_TEXT, 1);

            // タスク統計
            let task_y = y + 35;
            let task_str = format!(
                "Tasks: Active={} | Yields={} | Preemptions={}",
                snap.tasks.active,
                snap.tasks.voluntary_yields,
                snap.tasks.forced_preemptions
            );
            draw_text(buffer, x, task_y, &task_str, COLOR_TEXT, 1);
        }
    }

    /// プロセスリスト領域
    fn process_list_rect(&self) -> Rect {
        Rect::new(10, 240, WINDOW_WIDTH - 20, WINDOW_HEIGHT - 250)
    }

    /// プロセスリストを描画
    fn render_process_list(&self, buffer: &mut Image) {
        let rect = self.process_list_rect();
        let x = rect.x;
        let y = rect.y;
        let w = rect.width;
        let h = rect.height;

        // 背景
        buffer.fill_rect(rect, COLOR_GRAPH_BG);
        draw_rect_outline(buffer, rect, COLOR_GRAPH_BORDER);

        // ヘッダー
        let header_y = y + 2;
        draw_text(buffer, x + 10, header_y, "PID", COLOR_HEADER, 1);
        draw_text(buffer, x + 80, header_y, "Name", COLOR_HEADER, 1);
        draw_text(buffer, x + 250, header_y, "State", COLOR_HEADER, 1);
        draw_text(buffer, x + 350, header_y, "CPU Time", COLOR_HEADER, 1);
        draw_text(buffer, x + 480, header_y, "Action", COLOR_HEADER, 1);

        // 区切り線
        let sep_y = y + 18;
        for sx in (x + 5)..(x + w as i32 - 5) {
            if sx >= 0 && sep_y >= 0 {
                buffer.set_pixel(sx as u32, sep_y as u32, COLOR_GRAPH_BORDER);
            }
        }

        // プロセス行
        let row_height = 20;
        let start_y = y + 22;
        let max_rows = ((h as i32 - 25) / row_height) as usize;

        for i in 0..max_rows {
            let idx = self.scroll_offset + i;
            if idx >= self.process_list.len() {
                break;
            }

            let entry = &self.process_list[idx];
            let row_y = start_y + (i as i32 * row_height);

            // 行の背景
            let row_rect = Rect::new(x + 2, row_y, w - 4, row_height as u32);
            let bg_color = if self.selected_process == Some(idx) {
                COLOR_ROW_SELECTED
            } else if i % 2 == 1 {
                COLOR_ROW_ALT
            } else {
                COLOR_GRAPH_BG
            };
            buffer.fill_rect(row_rect, bg_color);

            // PID
            let pid_str = format!("{}", entry.pid.as_u64());
            draw_text(buffer, x + 10, row_y + 2, &pid_str, COLOR_TEXT, 1);

            // 名前
            let name = if entry.name.len() > 20 {
                format!("{}...", &entry.name[..17])
            } else {
                entry.name.clone()
            };
            draw_text(buffer, x + 80, row_y + 2, &name, COLOR_TEXT, 1);

            // 状態
            let state_color = match entry.state {
                ProcessState::Running => Color::new(0, 150, 0),
                ProcessState::Blocked => Color::new(100, 100, 100),
                ProcessState::Zombie => Color::new(200, 0, 0),
                _ => COLOR_TEXT,
            };
            draw_text(buffer, x + 250, row_y + 2, entry.state_str(), state_color, 1);

            // CPU時間
            let time_str = format!("{} ms", entry.cpu_time_ms);
            draw_text(buffer, x + 350, row_y + 2, &time_str, COLOR_TEXT, 1);

            // Killボタン
            let btn_rect = Rect::new(x + 480, row_y + 2, 50, 16);
            buffer.fill_rect(btn_rect, COLOR_KILL_BUTTON);
            draw_text(buffer, x + 490, row_y + 3, "Kill", COLOR_KILL_TEXT, 1);
        }

        // スクロールインジケーター
        if self.process_list.len() > max_rows {
            let scroll_info = format!(
                "{}-{} / {}",
                self.scroll_offset + 1,
                (self.scroll_offset + max_rows).min(self.process_list.len()),
                self.process_list.len()
            );
            draw_text(buffer, x + w as i32 - 100, y + h as i32 - 15, &scroll_info, COLOR_TEXT, 1);
        }
    }

    /// Killボタン領域を取得
    pub fn kill_button_rect(&self, process_index: usize) -> Option<Rect> {
        let rect = self.process_list_rect();
        let row_height = 20;
        let start_y = rect.y + 22;

        if process_index < self.scroll_offset {
            return None;
        }
        let visible_index = process_index - self.scroll_offset;
        let max_rows = ((rect.height as i32 - 25) / row_height) as usize;
        if visible_index >= max_rows {
            return None;
        }

        let row_y = start_y + (visible_index as i32 * row_height);
        Some(Rect::new(rect.x + 480, row_y + 2, 50, 16))
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// バイト数をフォーマット
fn format_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

/// 矩形の外枠を描画
fn draw_rect_outline(buffer: &mut Image, rect: Rect, color: Color) {
    let x0 = rect.x.max(0) as u32;
    let y0 = rect.y.max(0) as u32;
    let x1 = (rect.x + rect.width as i32 - 1).max(0) as u32;
    let y1 = (rect.y + rect.height as i32 - 1).max(0) as u32;
    
    // 上辺
    for x in x0..=x1 {
        buffer.set_pixel(x, y0, color);
    }
    // 下辺
    for x in x0..=x1 {
        buffer.set_pixel(x, y1, color);
    }
    // 左辺
    for y in y0..=y1 {
        buffer.set_pixel(x0, y, color);
    }
    // 右辺
    for y in y0..=y1 {
        buffer.set_pixel(x1, y, color);
    }
}

/// 簡易テキスト描画 (ビットマップフォント)
/// scale: 1 = 通常, 2 = 2倍サイズ
fn draw_text(buffer: &mut Image, x: i32, y: i32, text: &str, color: Color, scale: i32) {
    let mut cursor_x = x;
    let char_width = 6 * scale;

    for ch in text.chars() {
        if ch == ' ' {
            cursor_x += char_width;
            continue;
        }

        if let Some(bitmap) = get_char_bitmap(ch) {
            for (row, bits) in bitmap.iter().enumerate() {
                for col in 0..6 {
                    if (bits >> (5 - col)) & 1 == 1 {
                        // スケーリング
                        for sy in 0..scale {
                            for sx in 0..scale {
                                let px = cursor_x + col * scale + sx;
                                let py = y + (row as i32) * scale + sy;
                                if px >= 0 && py >= 0 {
                                    buffer.set_pixel(px as u32, py as u32, color);
                                }
                            }
                        }
                    }
                }
            }
        }
        cursor_x += char_width;
    }
}

/// 線を描画 (Bresenham)
fn draw_line(buffer: &mut Image, x0: i32, y0: i32, x1: i32, y1: i32, color: Color) {
    let dx = (x1 - x0).abs();
    let dy = -(y1 - y0).abs();
    let sx = if x0 < x1 { 1 } else { -1 };
    let sy = if y0 < y1 { 1 } else { -1 };
    let mut err = dx + dy;
    let mut x = x0;
    let mut y = y0;

    loop {
        if x >= 0 && y >= 0 {
            buffer.set_pixel(x as u32, y as u32, color);
        }
        if x == x1 && y == y1 {
            break;
        }
        let e2 = 2 * err;
        if e2 >= dy {
            if x == x1 {
                break;
            }
            err += dy;
            x += sx;
        }
        if e2 <= dx {
            if y == y1 {
                break;
            }
            err += dx;
            y += sy;
        }
    }
}

/// 簡易ビットマップフォント (6x8)
fn get_char_bitmap(ch: char) -> Option<[u8; 8]> {
    // 最小限の文字セット
    Some(match ch {
        '0' => [0x3C, 0x66, 0x6E, 0x76, 0x66, 0x66, 0x3C, 0x00],
        '1' => [0x18, 0x38, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00],
        '2' => [0x3C, 0x66, 0x06, 0x0C, 0x18, 0x30, 0x7E, 0x00],
        '3' => [0x3C, 0x66, 0x06, 0x1C, 0x06, 0x66, 0x3C, 0x00],
        '4' => [0x0C, 0x1C, 0x3C, 0x6C, 0x7E, 0x0C, 0x0C, 0x00],
        '5' => [0x7E, 0x60, 0x7C, 0x06, 0x06, 0x66, 0x3C, 0x00],
        '6' => [0x1C, 0x30, 0x60, 0x7C, 0x66, 0x66, 0x3C, 0x00],
        '7' => [0x7E, 0x06, 0x0C, 0x18, 0x18, 0x18, 0x18, 0x00],
        '8' => [0x3C, 0x66, 0x66, 0x3C, 0x66, 0x66, 0x3C, 0x00],
        '9' => [0x3C, 0x66, 0x66, 0x3E, 0x06, 0x0C, 0x38, 0x00],
        'A' | 'a' => [0x18, 0x3C, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x00],
        'B' | 'b' => [0x7C, 0x66, 0x66, 0x7C, 0x66, 0x66, 0x7C, 0x00],
        'C' | 'c' => [0x3C, 0x66, 0x60, 0x60, 0x60, 0x66, 0x3C, 0x00],
        'D' | 'd' => [0x78, 0x6C, 0x66, 0x66, 0x66, 0x6C, 0x78, 0x00],
        'E' | 'e' => [0x7E, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x7E, 0x00],
        'F' | 'f' => [0x7E, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x60, 0x00],
        'G' | 'g' => [0x3C, 0x66, 0x60, 0x6E, 0x66, 0x66, 0x3E, 0x00],
        'H' | 'h' => [0x66, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x66, 0x00],
        'I' | 'i' => [0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00],
        'J' | 'j' => [0x3E, 0x0C, 0x0C, 0x0C, 0x0C, 0x6C, 0x38, 0x00],
        'K' | 'k' => [0x66, 0x6C, 0x78, 0x70, 0x78, 0x6C, 0x66, 0x00],
        'L' | 'l' => [0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x7E, 0x00],
        'M' | 'm' => [0x63, 0x77, 0x7F, 0x6B, 0x63, 0x63, 0x63, 0x00],
        'N' | 'n' => [0x66, 0x76, 0x7E, 0x7E, 0x6E, 0x66, 0x66, 0x00],
        'O' | 'o' => [0x3C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00],
        'P' | 'p' => [0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60, 0x60, 0x00],
        'Q' | 'q' => [0x3C, 0x66, 0x66, 0x66, 0x6A, 0x6C, 0x36, 0x00],
        'R' | 'r' => [0x7C, 0x66, 0x66, 0x7C, 0x6C, 0x66, 0x66, 0x00],
        'S' | 's' => [0x3C, 0x66, 0x60, 0x3C, 0x06, 0x66, 0x3C, 0x00],
        'T' | 't' => [0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00],
        'U' | 'u' => [0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00],
        'V' | 'v' => [0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x00],
        'W' | 'w' => [0x63, 0x63, 0x63, 0x6B, 0x7F, 0x77, 0x63, 0x00],
        'X' | 'x' => [0x66, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x66, 0x00],
        'Y' | 'y' => [0x66, 0x66, 0x66, 0x3C, 0x18, 0x18, 0x18, 0x00],
        'Z' | 'z' => [0x7E, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x7E, 0x00],
        '%' => [0x62, 0x64, 0x08, 0x10, 0x26, 0x46, 0x00, 0x00],
        '/' => [0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x00, 0x00],
        '|' => [0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00],
        '=' => [0x00, 0x00, 0x7E, 0x00, 0x7E, 0x00, 0x00, 0x00],
        ':' => [0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x00, 0x00],
        '.' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00],
        '-' => [0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00],
        '(' => [0x0C, 0x18, 0x30, 0x30, 0x30, 0x18, 0x0C, 0x00],
        ')' => [0x30, 0x18, 0x0C, 0x0C, 0x0C, 0x18, 0x30, 0x00],
        _ => return None,
    })
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_monitor_creation() {
        let monitor = SystemMonitor::new();
        assert!(monitor.is_running());
        assert_eq!(monitor.cpu_history.len(), CPU_HISTORY_SIZE);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GB");
    }
}
