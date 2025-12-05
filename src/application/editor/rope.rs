// ============================================================================
// src/application/editor/rope.rs - Rope Data Structure
// ============================================================================
//!
//! # Rope - 効率的なテキストデータ構造
//!
//! 小さいチャンクに分割することで、挿入・削除を効率化

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::format;
use core::cmp::min;

/// チャンクの最大サイズ
const CHUNK_SIZE: usize = 512;

/// Ropeノード - テキストを効率的に管理
#[derive(Clone)]
pub struct RopeNode {
    /// テキストチャンク（リーフノードの場合）
    text: Option<String>,
    /// 左の子ノード
    left: Option<Box<RopeNode>>,
    /// 右の子ノード
    right: Option<Box<RopeNode>>,
    /// このノード以下の総文字数
    length: usize,
    /// このノード以下の総行数
    line_count: usize,
}

impl RopeNode {
    /// 空のノードを作成
    pub fn new() -> Self {
        Self {
            text: Some(String::new()),
            left: None,
            right: None,
            length: 0,
            line_count: 1,
        }
    }

    /// テキストからノードを作成
    pub fn from_str(s: &str) -> Self {
        if s.len() <= CHUNK_SIZE {
            let line_count = s.chars().filter(|&c| c == '\n').count() + 1;
            Self {
                text: Some(String::from(s)),
                left: None,
                right: None,
                length: s.len(),
                line_count,
            }
        } else {
            // 大きいテキストは分割
            let mid = s.len() / 2;
            // 改行位置で分割を試みる
            let split_pos = s[..mid].rfind('\n')
                .map(|p| p + 1)
                .unwrap_or(mid);
            
            let left = Box::new(RopeNode::from_str(&s[..split_pos]));
            let right = Box::new(RopeNode::from_str(&s[split_pos..]));
            
            let length = left.length + right.length;
            let line_count = left.line_count + right.line_count - 1;
            
            Self {
                text: None,
                left: Some(left),
                right: Some(right),
                length,
                line_count,
            }
        }
    }

    /// 長さを取得
    pub fn len(&self) -> usize {
        self.length
    }

    /// 空かどうか
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// 行数を取得
    pub fn lines(&self) -> usize {
        self.line_count
    }

    /// 指定位置の文字を取得
    pub fn char_at(&self, index: usize) -> Option<char> {
        if index >= self.length {
            return None;
        }

        if let Some(ref text) = self.text {
            text.chars().nth(index)
        } else {
            let left = self.left.as_ref()?;
            if index < left.length {
                left.char_at(index)
            } else {
                self.right.as_ref()?.char_at(index - left.length)
            }
        }
    }

    /// 指定範囲のテキストを取得
    pub fn slice(&self, start: usize, end: usize) -> String {
        if start >= end || start >= self.length {
            return String::new();
        }
        let end = min(end, self.length);

        if let Some(ref text) = self.text {
            text.chars().skip(start).take(end - start).collect()
        } else {
            let left = self.left.as_ref().unwrap();
            let right = self.right.as_ref().unwrap();
            
            let mut result = String::new();
            
            if start < left.length {
                result.push_str(&left.slice(start, min(end, left.length)));
            }
            if end > left.length {
                let right_start = start.saturating_sub(left.length);
                let right_end = end - left.length;
                result.push_str(&right.slice(right_start, right_end));
            }
            
            result
        }
    }

    /// 指定位置に文字列を挿入
    pub fn insert(&mut self, index: usize, s: &str) {
        if s.is_empty() {
            return;
        }

        let new_lines = s.chars().filter(|&c| c == '\n').count();

        if let Some(ref mut text) = self.text {
            // リーフノードへの挿入
            let byte_index = text.chars().take(index).map(|c| c.len_utf8()).sum();
            text.insert_str(byte_index, s);
            self.length += s.len();
            self.line_count += new_lines;

            // チャンクが大きくなりすぎたら分割
            if text.len() > CHUNK_SIZE * 2 {
                self.split_node();
            }
        } else {
            // 内部ノード
            let left = self.left.as_mut().unwrap();
            if index <= left.length {
                left.insert(index, s);
            } else {
                self.right.as_mut().unwrap().insert(index - left.length, s);
            }
            self.length += s.len();
            self.line_count += new_lines;
        }
    }

    /// ノードを分割
    fn split_node(&mut self) {
        if let Some(text) = self.text.take() {
            let mid = text.len() / 2;
            let split_pos = text[..mid].rfind('\n')
                .map(|p| p + 1)
                .unwrap_or(mid);
            
            let (left_text, right_text) = text.split_at(split_pos);
            
            self.left = Some(Box::new(RopeNode::from_str(left_text)));
            self.right = Some(Box::new(RopeNode::from_str(right_text)));
        }
    }

    /// 指定範囲を削除
    pub fn delete(&mut self, start: usize, end: usize) {
        if start >= end || start >= self.length {
            return;
        }
        let end = min(end, self.length);
        
        // 削除される改行数をカウント
        let deleted = self.slice(start, end);
        let deleted_lines = deleted.chars().filter(|&c| c == '\n').count();

        if let Some(ref mut text) = self.text {
            let byte_start: usize = text.chars().take(start).map(|c| c.len_utf8()).sum();
            let byte_end: usize = text.chars().take(end).map(|c| c.len_utf8()).sum();
            text.replace_range(byte_start..byte_end, "");
            self.length = text.chars().count();
            self.line_count = self.line_count.saturating_sub(deleted_lines);
        } else {
            let left = self.left.as_mut().unwrap();
            let right = self.right.as_mut().unwrap();
            
            if end <= left.length {
                left.delete(start, end);
            } else if start >= left.length {
                right.delete(start - left.length, end - left.length);
            } else {
                // 両方にまたがる削除
                left.delete(start, left.length);
                right.delete(0, end - left.length);
            }
            
            self.length = left.length + right.length;
            self.line_count = left.line_count + right.line_count - 1;
            
            // ノードが小さくなったらマージ
            if self.length <= CHUNK_SIZE {
                self.merge_nodes();
            }
        }
    }

    /// 子ノードをマージ
    fn merge_nodes(&mut self) {
        if self.text.is_none() {
            let left_text = self.left.as_ref().map(|n| n.to_string()).unwrap_or_default();
            let right_text = self.right.as_ref().map(|n| n.to_string()).unwrap_or_default();
            
            self.text = Some(format!("{}{}", left_text, right_text));
            self.left = None;
            self.right = None;
        }
    }

    /// 全テキストを文字列として取得
    pub fn to_string(&self) -> String {
        if let Some(ref text) = self.text {
            text.clone()
        } else {
            let left = self.left.as_ref().map(|n| n.to_string()).unwrap_or_default();
            let right = self.right.as_ref().map(|n| n.to_string()).unwrap_or_default();
            format!("{}{}", left, right)
        }
    }

    /// 行のテキストを取得
    pub fn get_line(&self, line_index: usize) -> String {
        let text = self.to_string();
        text.lines().nth(line_index).map(String::from).unwrap_or_default()
    }

    /// 行の開始位置（文字インデックス）を取得
    pub fn line_start(&self, line_index: usize) -> usize {
        if line_index == 0 {
            return 0;
        }
        
        let text = self.to_string();
        let mut pos = 0;
        let mut current_line = 0;
        
        for ch in text.chars() {
            if current_line == line_index {
                return pos;
            }
            if ch == '\n' {
                current_line += 1;
            }
            pos += 1;
        }
        
        pos
    }

    /// 行の終了位置（文字インデックス）を取得
    pub fn line_end(&self, line_index: usize) -> usize {
        let start = self.line_start(line_index);
        let text = self.to_string();
        
        let mut pos = start;
        for ch in text.chars().skip(start) {
            if ch == '\n' {
                return pos;
            }
            pos += 1;
        }
        
        pos
    }

    /// 文字位置から行番号を取得
    pub fn line_of(&self, char_index: usize) -> usize {
        let text = self.to_string();
        text.chars().take(char_index).filter(|&c| c == '\n').count()
    }

    /// 文字位置から列番号を取得
    pub fn column_of(&self, char_index: usize) -> usize {
        let line = self.line_of(char_index);
        let line_start = self.line_start(line);
        char_index - line_start
    }
}

impl Default for RopeNode {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rope_new() {
        let rope = RopeNode::new();
        assert_eq!(rope.len(), 0);
        assert_eq!(rope.lines(), 1);
    }

    #[test]
    fn test_rope_from_str() {
        let rope = RopeNode::from_str("Hello\nWorld");
        assert_eq!(rope.len(), 11);
        assert_eq!(rope.lines(), 2);
    }

    #[test]
    fn test_rope_insert() {
        let mut rope = RopeNode::from_str("Hello");
        rope.insert(5, " World");
        assert_eq!(rope.to_string(), "Hello World");
    }

    #[test]
    fn test_rope_delete() {
        let mut rope = RopeNode::from_str("Hello World");
        rope.delete(5, 11);
        assert_eq!(rope.to_string(), "Hello");
    }
}
