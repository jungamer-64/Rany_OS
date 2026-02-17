use super::*;


impl VirtualConsole {
    pub fn new(id: u32, cols: usize, rows: usize) -> Self {
        Self {
            id,
            buffer: TerminalBuffer::new(cols, rows),
            parser: AnsiParser::new(),
            saved_cursor: None,
            active: AtomicBool::new(false),
        }
    }

    /// 文字列を書き込む
    pub fn write(&mut self, s: &str) {
        for ch in s.chars() {
            if let Some(action) = self.parser.feed(ch) {
                self.execute_action(action);
            }
        }
    }

    /// ANSIアクションを実行
    fn execute_action(&mut self, action: AnsiAction) {
        match action {
            AnsiAction::Print(ch) => {
                self.buffer.write_char(ch);
            }
            AnsiAction::CursorUp(n) => {
                let (x, y) = self.buffer.cursor();
                self.buffer.set_cursor(x, y.saturating_sub(n));
            }
            AnsiAction::CursorDown(n) => {
                let (x, y) = self.buffer.cursor();
                self.buffer.set_cursor(x, y + n);
            }
            AnsiAction::CursorForward(n) => {
                let (x, y) = self.buffer.cursor();
                self.buffer.set_cursor(x + n, y);
            }
            AnsiAction::CursorBack(n) => {
                let (x, y) = self.buffer.cursor();
                self.buffer.set_cursor(x.saturating_sub(n), y);
            }
            AnsiAction::SetCursor { row, col } => {
                self.buffer.set_cursor(col, row);
            }
            AnsiAction::ClearScreen(mode) => {
                self.buffer.clear_screen(mode);
            }
            AnsiAction::ClearLine(mode) => {
                self.buffer.clear_line(mode);
            }
            AnsiAction::SetGraphics(params) => {
                self.apply_sgr(&params);
            }
            AnsiAction::SaveCursor => {
                self.saved_cursor = Some(self.buffer.cursor());
            }
            AnsiAction::RestoreCursor => {
                if let Some((x, y)) = self.saved_cursor {
                    self.buffer.set_cursor(x, y);
                }
            }
            AnsiAction::ReportCursor => {
                // カーソル位置レポート（エコーバック用）
            }
            AnsiAction::Reset => {
                self.buffer.clear();
                self.buffer.set_attributes(CharAttributes::new());
            }
        }
    }

    /// SGRパラメータを適用
    fn apply_sgr(&mut self, params: &[u32]) {
        let mut attr = self.buffer.current_attr;
        let mut i = 0;

        while i < params.len() {
            match params[i] {
                0 => attr = CharAttributes::new(),
                1 => attr.bold = true,
                4 => attr.underline = true,
                5 => attr.blink = true,
                7 => attr.inverse = true,
                22 => attr.bold = false,
                24 => attr.underline = false,
                25 => attr.blink = false,
                27 => attr.inverse = false,
                30..=37 => {
                    if let Some(c) = AnsiColor::from_sgr((params[i] - 30) as u8, attr.bold) {
                        attr.fg_color = c;
                    }
                }
                40..=47 => {
                    if let Some(c) = AnsiColor::from_sgr((params[i] - 40) as u8, false) {
                        attr.bg_color = c;
                    }
                }
                90..=97 => {
                    if let Some(c) = AnsiColor::from_sgr((params[i] - 90) as u8, true) {
                        attr.fg_color = c;
                    }
                }
                100..=107 => {
                    if let Some(c) = AnsiColor::from_sgr((params[i] - 100) as u8, true) {
                        attr.bg_color = c;
                    }
                }
                _ => {}
            }
            i += 1;
        }

        self.buffer.set_attributes(attr);
    }

    /// バッファを取得
    pub fn buffer(&self) -> &TerminalBuffer {
        &self.buffer
    }

    /// アクティブ状態を設定
    pub fn set_active(&self, active: bool) {
        self.active.store(active, Ordering::Release);
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    /// スクロールビュー
    pub fn scroll_view(&mut self, delta: isize) {
        self.buffer.scroll_view(delta);
    }

    /// ビューをリセット
    pub fn reset_view(&mut self) {
        self.buffer.reset_view();
    }
}

// ============================================================================
// Console Manager
// ============================================================================

/// コンソールマネージャー
pub struct ConsoleManager {
    /// 仮想コンソール
    consoles: Vec<Mutex<VirtualConsole>>,
    /// 現在アクティブなコンソール
    active: AtomicU32,
    /// 列数
    cols: usize,
    /// 行数
    rows: usize,
}

impl ConsoleManager {
    pub fn new(cols: usize, rows: usize) -> Self {
        let mut consoles = Vec::with_capacity(MAX_VIRTUAL_CONSOLES);
        for i in 0..MAX_VIRTUAL_CONSOLES {
            let vc = VirtualConsole::new(i as u32, cols, rows);
            consoles.push(Mutex::new(vc));
        }

        // 最初のコンソールをアクティブに
        consoles[0].lock().set_active(true);

        Self {
            consoles,
            active: AtomicU32::new(0),
            cols,
            rows,
        }
    }

    /// アクティブなコンソールに書き込む
    pub fn write(&self, s: &str) {
        let active = self.active.load(Ordering::Acquire) as usize;
        if let Some(console) = self.consoles.get(active) {
            console.lock().write(s);
        }
    }

    /// アクティブなコンソールに書き込む (Non-blocking)
    pub fn try_write(&self, s: &str) {
        let active = self.active.load(Ordering::Acquire) as usize;
        if let Some(console) = self.consoles.get(active) {
            if let Some(mut locked_console) = console.try_lock() {
                locked_console.write(s);
            }
        }
    }

    /// 指定コンソールに書き込む
    pub fn write_to(&self, console_id: u32, s: &str) {
        if let Some(console) = self.consoles.get(console_id as usize) {
            console.lock().write(s);
        }
    }

    /// アクティブなコンソールをスクロール
    pub fn scroll_view(&self, delta: isize) {
        let active = self.active.load(Ordering::Acquire);
         if let Some(console) = self.consoles.get(active as usize) {
            console.lock().scroll_view(delta);
        }
    }


    /// コンソールを切り替え
    pub fn switch_to(&self, console_id: u32) {
        let id = console_id as usize;
        if id >= self.consoles.len() {
            return;
        }

        let old_active = self.active.swap(console_id, Ordering::AcqRel) as usize;

        if let Some(old) = self.consoles.get(old_active) {
            old.lock().set_active(false);
        }

        if let Some(new) = self.consoles.get(id) {
            new.lock().set_active(true);
        }
    }

    /// 現在のコンソールIDを取得
    pub fn active_console(&self) -> u32 {
        self.active.load(Ordering::Acquire)
    }

    /// コンソールにアクセス
    pub fn with_console<F, R>(&self, console_id: u32, f: F) -> Option<R>
    where
        F: FnOnce(&mut VirtualConsole) -> R,
    {
        self.consoles
            .get(console_id as usize)
            .map(|c| f(&mut c.lock()))
    }

    /// 次のコンソールに切り替え
    pub fn switch_next(&self) {
        let current = self.active.load(Ordering::Acquire);
        let next = (current + 1) % (self.consoles.len() as u32);
        self.switch_to(next);
    }

    /// 前のコンソールに切り替え
    pub fn switch_prev(&self) {
        let current = self.active.load(Ordering::Acquire);
        let prev = if current == 0 {
            (self.consoles.len() - 1) as u32
        } else {
            current - 1
        };
        self.switch_to(prev);
    }
}

// ============================================================================
// Console Driver Trait
// ============================================================================

/// コンソール描画ドライバー
///
/// コンソールマネージャーからの出力を実際に画面に描画するためのトレイト
pub trait ConsoleDriver: Send {
    /// バッファの内容を画面に反映
    ///
    /// buffer: 描画すべき端末バッファ
    /// full_redraw: 画面全体の再描画が必要かどうか
    fn flush(&mut self, buffer: &TerminalBuffer);
}

// ============================================================================
// Global Instance
// ============================================================================

pub(crate) static CONSOLE_MANAGER: Mutex<Option<ConsoleManager>> = Mutex::new(None);
pub(crate) static CONSOLE_DRIVER: Mutex<Option<Box<dyn ConsoleDriver>>> = Mutex::new(None);

/// コンソールシステムを初期化
pub fn init(cols: usize, rows: usize) {
    *CONSOLE_MANAGER.lock() = Some(ConsoleManager::new(cols, rows));
}

/// デフォルト設定で初期化
pub fn init_default() {
    init(DEFAULT_COLS, DEFAULT_ROWS);
}

/// ドライバを設定
pub fn set_driver(driver: Box<dyn ConsoleDriver>) {
    *CONSOLE_DRIVER.lock() = Some(driver);
    // 初期描画のためにフラッシュ
    flush_screen();
}

/// 画面を強制的にフラッシュ
pub fn flush_screen() {
    if let Some(ref manager) = *CONSOLE_MANAGER.lock() {
        if let Some(ref mut driver) = *CONSOLE_DRIVER.lock() {
             let active = manager.active_console();
             if let Some(console) = manager.consoles.get(active as usize) {
                 // Use .buffer() getter as the field is private
                 driver.flush(console.lock().buffer());
             }
        }
    }
}

/// コンソールに書き込む (Blocking)
pub fn write(s: &str) {
    {
        if let Some(ref manager) = *CONSOLE_MANAGER.lock() {
            manager.write(s);
        }
    }
    // 書き込み後にフラッシュ
    flush_screen();
}

/// コンソールに書き込む (Non-blocking / Try Lock)
/// 割り込みハンドラやロガーからの呼び出し用
pub fn try_write(s: &str) {
    // Try to lock manager
    if let Some(guard) = CONSOLE_MANAGER.try_lock() {
        if let Some(ref manager) = *guard {
             manager.try_write(s);
        }
    }

    // Try to flush (best effort)
    if let Some(manager_guard) = CONSOLE_MANAGER.try_lock() {
        if let Some(ref manager) = *manager_guard {
            if let Some(mut driver_guard) = CONSOLE_DRIVER.try_lock() {
                if let Some(ref mut driver) = *driver_guard {
                     let active = manager.active_console();
                     if let Some(console) = manager.consoles.get(active as usize) {
                         // Try lock console
                         if let Some(locked_console) = console.try_lock() {
                             driver.flush(locked_console.buffer());
                         }
                     }
                }
            }
        }
    }
}

/// コンソールマネージャーにアクセス
pub fn with_manager<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&ConsoleManager) -> R,
{
    CONSOLE_MANAGER.lock().as_ref().map(f)
}

/// コンソールを切り替え
pub fn switch(console_id: u32) {
    if let Some(ref manager) = *CONSOLE_MANAGER.lock() {
        manager.switch_to(console_id);
    }
    flush_screen();
}

/// アクティブなコンソールをスクロール
pub fn scroll(delta: isize) {
     if let Some(ref manager) = *CONSOLE_MANAGER.lock() {
        manager.scroll_view(delta);
    }
    flush_screen();
} 

// ============================================================================
// Print Macros
// ============================================================================

/// コンソールにフォーマット出力
#[macro_export]
macro_rules! console_print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        use alloc::string::ToString;
        let s = alloc::format!($($arg)*);
        $crate::console::write(&s);
    }};
}

/// コンソールにフォーマット出力（改行付き）
#[macro_export]
macro_rules! console_println {
    () => {
        $crate::console::write("\n");
    };
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        use alloc::string::ToString;
        let s = alloc::format!($($arg)*);
        $crate::console::write(&s);
        $crate::console::write("\n");
    }};
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests;

