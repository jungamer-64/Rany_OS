// ============================================================================
// src/monitor/display.rs - Monitor Display Utilities
// ============================================================================

use alloc::string::String;
use alloc::vec::Vec;

/// ANSI escape codes for terminal formatting
pub mod ansi {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";
    
    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const BLUE: &str = "\x1b[34m";
    pub const MAGENTA: &str = "\x1b[35m";
    pub const CYAN: &str = "\x1b[36m";
    pub const WHITE: &str = "\x1b[37m";
    
    pub const BG_RED: &str = "\x1b[41m";
    pub const BG_GREEN: &str = "\x1b[42m";
    pub const BG_BLUE: &str = "\x1b[44m";
    
    pub const CLEAR_SCREEN: &str = "\x1b[2J";
    pub const HOME: &str = "\x1b[H";
    pub const CLEAR_LINE: &str = "\x1b[2K";
}

/// Box drawing characters
pub mod box_chars {
    pub const TOP_LEFT: char = '┌';
    pub const TOP_RIGHT: char = '┐';
    pub const BOTTOM_LEFT: char = '└';
    pub const BOTTOM_RIGHT: char = '┘';
    pub const HORIZONTAL: char = '─';
    pub const VERTICAL: char = '│';
    pub const T_LEFT: char = '├';
    pub const T_RIGHT: char = '┤';
    pub const T_TOP: char = '┬';
    pub const T_BOTTOM: char = '┴';
    pub const CROSS: char = '┼';
}

/// Progress bar renderer
pub struct ProgressBar {
    width: usize,
    filled_char: char,
    empty_char: char,
}

impl ProgressBar {
    pub fn new(width: usize) -> Self {
        ProgressBar {
            width,
            filled_char: '█',
            empty_char: '░',
        }
    }
    
    pub fn with_chars(mut self, filled: char, empty: char) -> Self {
        self.filled_char = filled;
        self.empty_char = empty;
        self
    }
    
    /// Render progress bar as string
    pub fn render(&self, percent: u8) -> String {
        let filled = (percent as usize * self.width) / 100;
        let mut bar = String::with_capacity(self.width + 2);
        
        bar.push('[');
        for i in 0..self.width {
            if i < filled {
                bar.push(self.filled_char);
            } else {
                bar.push(self.empty_char);
            }
        }
        bar.push(']');
        
        bar
    }
    
    /// Render with percentage label
    pub fn render_with_label(&self, percent: u8) -> String {
        alloc::format!("{} {:>3}%", self.render(percent), percent)
    }
}

/// Sparkline renderer (mini graph)
pub struct Sparkline {
    chars: [char; 8],
}

impl Sparkline {
    pub fn new() -> Self {
        Sparkline {
            chars: ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'],
        }
    }
    
    /// Render values as sparkline
    pub fn render(&self, values: &[u8]) -> String {
        values.iter()
            .map(|&v| {
                let idx = (v as usize * 7) / 100;
                self.chars[idx.min(7)]
            })
            .collect()
    }
}

/// Format bytes as human-readable string
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;
    
    if bytes >= TB {
        alloc::format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        alloc::format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        alloc::format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        alloc::format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        alloc::format!("{} B", bytes)
    }
}

/// Format duration in ticks as human-readable
pub fn format_duration(ticks: u64) -> String {
    // Assuming ~1000 ticks per second (depends on timer config)
    const TICKS_PER_SEC: u64 = 1000;
    
    let seconds = ticks / TICKS_PER_SEC;
    let minutes = seconds / 60;
    let hours = minutes / 60;
    let days = hours / 24;
    
    if days > 0 {
        alloc::format!("{}d {}h {}m", days, hours % 24, minutes % 60)
    } else if hours > 0 {
        alloc::format!("{}h {}m {}s", hours, minutes % 60, seconds % 60)
    } else if minutes > 0 {
        alloc::format!("{}m {}s", minutes, seconds % 60)
    } else {
        alloc::format!("{}s", seconds)
    }
}

/// Table renderer
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
    column_widths: Vec<usize>,
}

impl Table {
    pub fn new(headers: Vec<&str>) -> Self {
        let headers: Vec<String> = headers.into_iter().map(String::from).collect();
        let column_widths = headers.iter().map(|h| h.len()).collect();
        
        Table {
            headers,
            rows: Vec::new(),
            column_widths,
        }
    }
    
    pub fn add_row(&mut self, row: Vec<&str>) {
        let row: Vec<String> = row.into_iter().map(String::from).collect();
        
        // Update column widths
        for (i, cell) in row.iter().enumerate() {
            if i < self.column_widths.len() {
                self.column_widths[i] = self.column_widths[i].max(cell.len());
            }
        }
        
        self.rows.push(row);
    }
    
    /// Render table as string
    pub fn render(&self) -> String {
        let mut output = String::new();
        
        // Calculate total width
        let total_width: usize = self.column_widths.iter().sum::<usize>() 
            + (self.column_widths.len() * 3) + 1;
        
        // Top border
        output.push_str(&format!("{}", box_chars::TOP_LEFT));
        output.push_str(&format!("{}", box_chars::HORIZONTAL).repeat(total_width - 2));
        output.push_str(&format!("{}\n", box_chars::TOP_RIGHT));
        
        // Headers
        output.push_str(&format!("{} ", box_chars::VERTICAL));
        for (i, header) in self.headers.iter().enumerate() {
            let width = self.column_widths.get(i).copied().unwrap_or(10);
            output.push_str(&format!("{:^width$} ", header, width = width));
            output.push_str(&format!("{} ", box_chars::VERTICAL));
        }
        output.push('\n');
        
        // Header separator
        output.push_str(&format!("{}", box_chars::T_LEFT));
        output.push_str(&format!("{}", box_chars::HORIZONTAL).repeat(total_width - 2));
        output.push_str(&format!("{}\n", box_chars::T_RIGHT));
        
        // Rows
        for row in &self.rows {
            output.push_str(&format!("{} ", box_chars::VERTICAL));
            for (i, cell) in row.iter().enumerate() {
                let width = self.column_widths.get(i).copied().unwrap_or(10);
                output.push_str(&format!("{:>width$} ", cell, width = width));
                output.push_str(&format!("{} ", box_chars::VERTICAL));
            }
            output.push('\n');
        }
        
        // Bottom border
        output.push_str(&format!("{}", box_chars::BOTTOM_LEFT));
        output.push_str(&format!("{}", box_chars::HORIZONTAL).repeat(total_width - 2));
        output.push_str(&format!("{}\n", box_chars::BOTTOM_RIGHT));
        
        output
    }
}

/// Status indicator
#[derive(Clone, Copy)]
pub enum StatusIndicator {
    Ok,
    Warning,
    Error,
    Unknown,
}

impl StatusIndicator {
    pub fn symbol(&self) -> &'static str {
        match self {
            StatusIndicator::Ok => "✓",
            StatusIndicator::Warning => "⚠",
            StatusIndicator::Error => "✗",
            StatusIndicator::Unknown => "?",
        }
    }
    
    pub fn colored(&self) -> String {
        match self {
            StatusIndicator::Ok => alloc::format!("{}{}{}",ansi::GREEN, self.symbol(), ansi::RESET),
            StatusIndicator::Warning => alloc::format!("{}{}{}", ansi::YELLOW, self.symbol(), ansi::RESET),
            StatusIndicator::Error => alloc::format!("{}{}{}", ansi::RED, self.symbol(), ansi::RESET),
            StatusIndicator::Unknown => alloc::format!("{}{}{}", ansi::DIM, self.symbol(), ansi::RESET),
        }
    }
}
