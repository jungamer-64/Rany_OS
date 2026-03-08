// ============================================================================
// src/shell/line_buffer.rs - Interactive Line Buffer
// ============================================================================

use alloc::string::{String, ToString};

/// Maximum line buffer size
pub const MAX_LINE_LENGTH: usize = 256;

/// Line buffer for interactive editing
#[derive(Clone)]
pub struct LineBuffer {
    /// Buffer content
    pub content: String,
    /// Cursor position (character index)
    pub cursor: usize,
}

impl LineBuffer {
    pub fn new() -> Self {
        Self {
            content: String::new(),
            cursor: 0,
        }
    }

    pub fn reset(&mut self) {
        self.content.clear();
        self.cursor = 0;
    }

    pub fn clear(&mut self) {
        self.reset();
    }

    pub fn insert(&mut self, c: char) {
        if self.content.len() < MAX_LINE_LENGTH {
            self.content.insert(self.cursor, c);
            self.cursor += 1;
        }
    }

    pub fn insert_str(&mut self, s: &str) {
        for c in s.chars() {
            self.insert(c);
        }
    }

    pub fn backspace(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            self.content.remove(self.cursor);
        }
    }

    pub fn delete(&mut self) {
        if self.cursor < self.content.len() {
            self.content.remove(self.cursor);
        }
    }

    pub fn move_left(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

    pub fn move_right(&mut self) {
        if self.cursor < self.content.len() {
            self.cursor += 1;
        }
    }

    pub fn move_home(&mut self) {
        self.cursor = 0;
    }

    pub fn move_end(&mut self) {
        self.cursor = self.content.len();
    }

    pub fn move_word_left(&mut self) {
        // Skip whitespace
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while self.cursor > 0 && self.content.chars().nth(self.cursor - 1) == Some(' ') {
            self.cursor -= 1;
        }
        // Move to start of word
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while self.cursor > 0 && self.content.chars().nth(self.cursor - 1) != Some(' ') {
            self.cursor -= 1;
        }
    }

    pub fn move_word_right(&mut self) {
        let len = self.content.len();
        // Move to end of word
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while self.cursor < len && self.content.chars().nth(self.cursor) != Some(' ') {
            self.cursor += 1;
        }
        // Skip whitespace
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while self.cursor < len && self.content.chars().nth(self.cursor) == Some(' ') {
            self.cursor += 1;
        }
    }

    pub fn delete_word(&mut self) {
        let start = self.cursor;
        self.move_word_left();
        let end = self.cursor;
        if start > end {
            self.content.drain(end..start);
        }
    }

    pub fn clear_to_end(&mut self) {
        self.content.truncate(self.cursor);
    }

    pub fn clear_to_start(&mut self) {
        self.content = self.content[self.cursor..].to_string();
        self.cursor = 0;
    }

    pub fn set(&mut self, s: &str) {
        self.content = s.to_string();
        self.cursor = self.content.len();
    }

    pub fn as_str(&self) -> &str {
        &self.content
    }

    pub fn len(&self) -> usize {
        self.content.len()
    }

    pub fn is_empty(&self) -> bool {
        self.content.is_empty()
    }
}

impl Default for LineBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn middle_insert_and_cursor_tracking() {
        let mut buf = LineBuffer::new();
        buf.insert('a');
        buf.insert('b');
        buf.insert('c');
        buf.move_left();
        buf.insert('X');
        assert_eq!(buf.as_str(), "abXc");
        assert_eq!(buf.cursor, 3);
    }

    #[test_case]
    fn delete_and_backspace_keep_expected_content() {
        let mut buf = LineBuffer::new();
        buf.insert_str("abcd");
        buf.move_left(); // cursor=3
        buf.backspace(); // remove 'c'
        assert_eq!(buf.as_str(), "abd");
        assert_eq!(buf.cursor, 2);
        buf.delete(); // remove 'd'
        assert_eq!(buf.as_str(), "ab");
        assert_eq!(buf.cursor, 2);
    }
}
