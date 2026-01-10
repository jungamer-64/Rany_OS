// ============================================================================
// src/shell/exoshell/history.rs - History Navigation Logic
// ============================================================================

use alloc::string::{String, ToString};


/// Shell history navigation state
/// 
/// Manages the state when navigating up/down through command history.
/// Does NOT store the history itself; the shell instance does that.
pub struct HistoryNavigator {
    index: Option<usize>,
    stash: String,
}

impl HistoryNavigator {
    pub fn new() -> Self {
        Self {
            index: None,
            stash: String::new(),
        }
    }

    /// Go back in history (Up key)
    pub fn prev(&mut self, history: &[String], current: &str) -> Option<String> {
        if history.is_empty() {
            return None;
        }

        match self.index {
            None => {
                // First time going back, stash current input
                self.stash = current.to_string();
                self.index = Some(history.len() - 1);
            }
            Some(0) => {
                // Already at oldest, do nothing
                return Some(history[0].clone());
            }
            Some(idx) => {
                self.index = Some(idx - 1);
            }
        }

        self.index.map(|i| history[i].clone())
    }

    /// Go forward in history (Down key)
    pub fn next(&mut self, history: &[String]) -> Option<String> {
        match self.index {
            None => None,
            Some(idx) => {
                if idx + 1 >= history.len() {
                    // Back to current input
                    self.index = None;
                    Some(self.stash.clone())
                } else {
                    self.index = Some(idx + 1);
                    Some(history[idx + 1].clone())
                }
            }
        }
    }

    /// Reset navigation state
    pub fn reset_navigation(&mut self) {
        self.index = None;
        self.stash.clear();
    }
}
