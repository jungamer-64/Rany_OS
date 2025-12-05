// ============================================================================
// src/application/browser/layout.rs - Layout Tree
// ============================================================================
//!
//! # レイアウトツリー
//!
//! スタイルツリーに基づき、各要素の座標とサイズを計算。

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::style::{StyledNode, Display};
use super::css::{Value, Unit};
use super::dom::NodeType;

// ============================================================================
// Dimensions
// ============================================================================

/// 矩形
#[derive(Debug, Clone, Copy, Default)]
pub struct Rect {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

impl Rect {
    pub fn new(x: f32, y: f32, width: f32, height: f32) -> Self {
        Self { x, y, width, height }
    }

    /// 右端
    pub fn right(&self) -> f32 {
        self.x + self.width
    }

    /// 下端
    pub fn bottom(&self) -> f32 {
        self.y + self.height
    }

    /// 拡張した矩形を返す
    pub fn expanded_by(&self, edge: EdgeSizes) -> Rect {
        Rect {
            x: self.x - edge.left,
            y: self.y - edge.top,
            width: self.width + edge.left + edge.right,
            height: self.height + edge.top + edge.bottom,
        }
    }
}

/// エッジサイズ（margin, padding, border）
#[derive(Debug, Clone, Copy, Default)]
pub struct EdgeSizes {
    pub top: f32,
    pub right: f32,
    pub bottom: f32,
    pub left: f32,
}

impl EdgeSizes {
    pub fn new(top: f32, right: f32, bottom: f32, left: f32) -> Self {
        Self { top, right, bottom, left }
    }

    pub fn uniform(size: f32) -> Self {
        Self::new(size, size, size, size)
    }
}

/// 寸法（コンテンツ領域 + padding + border + margin）
#[derive(Debug, Clone, Copy, Default)]
pub struct Dimensions {
    /// コンテンツ領域
    pub content: Rect,
    /// パディング
    pub padding: EdgeSizes,
    /// ボーダー
    pub border: EdgeSizes,
    /// マージン
    pub margin: EdgeSizes,
}

impl Dimensions {
    /// パディングボックス
    pub fn padding_box(&self) -> Rect {
        self.content.expanded_by(self.padding)
    }

    /// ボーダーボックス
    pub fn border_box(&self) -> Rect {
        self.padding_box().expanded_by(self.border)
    }

    /// マージンボックス
    pub fn margin_box(&self) -> Rect {
        self.border_box().expanded_by(self.margin)
    }
}

// ============================================================================
// Layout Box
// ============================================================================

/// ボックスタイプ
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BoxType {
    /// ブロックボックス
    Block,
    /// インラインボックス
    Inline,
    /// 匿名ブロック
    AnonymousBlock,
}

/// レイアウトボックス
#[derive(Debug)]
pub struct LayoutBox<'a> {
    /// 寸法
    pub dimensions: Dimensions,
    /// ボックスタイプ
    pub box_type: BoxType,
    /// スタイル付きノード（匿名の場合None）
    pub styled_node: Option<&'a StyledNode<'a>>,
    /// 子ボックス
    pub children: Vec<LayoutBox<'a>>,
}

impl<'a> LayoutBox<'a> {
    /// 新しいレイアウトボックスを作成
    pub fn new(box_type: BoxType) -> Self {
        Self {
            dimensions: Dimensions::default(),
            box_type,
            styled_node: None,
            children: Vec::new(),
        }
    }

    /// スタイル付きノードからレイアウトボックスを作成
    pub fn from_styled(styled_node: &'a StyledNode<'a>, box_type: BoxType) -> Self {
        Self {
            dimensions: Dimensions::default(),
            box_type,
            styled_node: Some(styled_node),
            children: Vec::new(),
        }
    }

    /// インライン子用の匿名ブロックを取得または作成
    fn get_inline_container(&mut self) -> &mut LayoutBox<'a> {
        match self.box_type {
            BoxType::Inline | BoxType::AnonymousBlock => self,
            BoxType::Block => {
                // 最後の子が匿名ブロックでなければ作成
                let needs_new = match self.children.last() {
                    Some(last) => last.box_type != BoxType::AnonymousBlock,
                    None => true,
                };
                if needs_new {
                    self.children.push(LayoutBox::new(BoxType::AnonymousBlock));
                }
                self.children.last_mut().unwrap()
            }
        }
    }
}

// ============================================================================
// Layout Tree Construction
// ============================================================================

/// レイアウトツリーを構築
pub fn layout_tree<'a>(
    styled_root: &'a StyledNode<'a>,
    containing_block: Dimensions,
) -> LayoutBox<'a> {
    // ルートボックスを作成
    let mut root = build_layout_tree(styled_root);

    // レイアウトを計算
    root.layout(containing_block);

    root
}

/// スタイルツリーからレイアウトツリーを構築
fn build_layout_tree<'a>(styled_node: &'a StyledNode<'a>) -> LayoutBox<'a> {
    // 表示タイプに基づいてボックスタイプを決定
    let box_type = match styled_node.display() {
        Display::Block => BoxType::Block,
        Display::Inline | Display::InlineBlock => BoxType::Inline,
        Display::None => {
            // display: none は空のボックス
            return LayoutBox::new(BoxType::Block);
        }
    };

    let mut root = LayoutBox::from_styled(styled_node, box_type);

    // 子要素を処理
    for child in &styled_node.children {
        match child.display() {
            Display::None => continue,
            Display::Block => {
                root.children.push(build_layout_tree(child));
            }
            Display::Inline | Display::InlineBlock => {
                let container = root.get_inline_container();
                container.children.push(build_layout_tree(child));
            }
        }
    }

    root
}

// ============================================================================
// Layout Calculation
// ============================================================================

impl<'a> LayoutBox<'a> {
    /// レイアウトを計算
    pub fn layout(&mut self, containing_block: Dimensions) {
        match self.box_type {
            BoxType::Block | BoxType::AnonymousBlock => {
                self.layout_block(containing_block);
            }
            BoxType::Inline => {
                self.layout_inline(containing_block);
            }
        }
    }

    /// ブロックボックスのレイアウト
    fn layout_block(&mut self, containing_block: Dimensions) {
        // 幅を計算
        self.calculate_block_width(containing_block);

        // 位置を計算
        self.calculate_block_position(containing_block);

        // 子要素をレイアウト
        self.layout_block_children();

        // 高さを計算
        self.calculate_block_height();
    }

    /// ブロックの幅を計算
    fn calculate_block_width(&mut self, containing_block: Dimensions) {
        let style = match self.styled_node {
            Some(s) => s,
            None => {
                // 匿名ブロック
                self.dimensions.content.width = containing_block.content.width;
                return;
            }
        };

        // auto を 0 として扱う
        let auto = Value::Keyword("auto".into());
        let zero = Value::Length(0.0, Unit::Px);

        let mut width = style.value("width").unwrap_or(&auto).clone();

        let margin_left = style.lookup("margin-left", "margin", &zero);
        let margin_right = style.lookup("margin-right", "margin", &zero);
        let padding_left = style.lookup("padding-left", "padding", &zero);
        let padding_right = style.lookup("padding-right", "padding", &zero);
        let border_left = style.lookup("border-left-width", "border-width", &zero);
        let border_right = style.lookup("border-right-width", "border-width", &zero);

        let total = margin_left.to_px()
            + margin_right.to_px()
            + padding_left.to_px()
            + padding_right.to_px()
            + border_left.to_px()
            + border_right.to_px();

        // width: auto の場合、残りの幅を使用
        if width == auto {
            let remaining = containing_block.content.width - total;
            width = Value::Length(remaining.max(0.0), Unit::Px);
        }

        self.dimensions.content.width = width.to_px();
        self.dimensions.padding.left = padding_left.to_px();
        self.dimensions.padding.right = padding_right.to_px();
        self.dimensions.border.left = border_left.to_px();
        self.dimensions.border.right = border_right.to_px();
        self.dimensions.margin.left = margin_left.to_px();
        self.dimensions.margin.right = margin_right.to_px();
    }

    /// ブロックの位置を計算
    fn calculate_block_position(&mut self, containing_block: Dimensions) {
        let style = match self.styled_node {
            Some(s) => s,
            None => {
                self.dimensions.content.x = containing_block.content.x;
                self.dimensions.content.y = containing_block.content.height
                    + containing_block.content.y;
                return;
            }
        };

        let zero = Value::Length(0.0, Unit::Px);

        self.dimensions.margin.top = style.lookup("margin-top", "margin", &zero).to_px();
        self.dimensions.margin.bottom = style.lookup("margin-bottom", "margin", &zero).to_px();
        self.dimensions.padding.top = style.lookup("padding-top", "padding", &zero).to_px();
        self.dimensions.padding.bottom = style.lookup("padding-bottom", "padding", &zero).to_px();
        self.dimensions.border.top = style.lookup("border-top-width", "border-width", &zero).to_px();
        self.dimensions.border.bottom = style.lookup("border-bottom-width", "border-width", &zero).to_px();

        // X座標
        self.dimensions.content.x = containing_block.content.x
            + self.dimensions.margin.left
            + self.dimensions.border.left
            + self.dimensions.padding.left;

        // Y座標（前のボックスの下）
        self.dimensions.content.y = containing_block.content.y
            + containing_block.content.height
            + self.dimensions.margin.top
            + self.dimensions.border.top
            + self.dimensions.padding.top;
    }

    /// 子要素をレイアウト
    fn layout_block_children(&mut self) {
        let d = self.dimensions;
        for child in &mut self.children {
            child.layout(d);
            // 高さを更新
            self.dimensions.content.height =
                self.dimensions.content.height + child.dimensions.margin_box().height;
        }
    }

    /// ブロックの高さを計算
    fn calculate_block_height(&mut self) {
        // 明示的な height が指定されていれば使用
        if let Some(style) = self.styled_node {
            if let Some(Value::Length(h, _)) = style.value("height") {
                self.dimensions.content.height = *h;
            }
        }
    }

    /// インラインボックスのレイアウト
    fn layout_inline(&mut self, containing_block: Dimensions) {
        let style = match self.styled_node {
            Some(s) => s,
            None => {
                return;
            }
        };

        // テキストノードの場合
        if let NodeType::Text(text) = &style.node.node_type {
            let font_size = style.length_px("font-size").max(16.0);
            let line_height = font_size * 1.2;

            // 文字幅を計算（簡易）
            let char_width = font_size * 0.6;
            let text_width = text.len() as f32 * char_width;

            self.dimensions.content.width = text_width.min(containing_block.content.width);
            self.dimensions.content.height = line_height;
        } else {
            // インライン要素
            let zero = Value::Length(0.0, Unit::Px);

            self.dimensions.padding.left = style.lookup("padding-left", "padding", &zero).to_px();
            self.dimensions.padding.right = style.lookup("padding-right", "padding", &zero).to_px();
            self.dimensions.margin.left = style.lookup("margin-left", "margin", &zero).to_px();
            self.dimensions.margin.right = style.lookup("margin-right", "margin", &zero).to_px();

            // 子要素をレイアウト
            let mut width = 0.0f32;
            let mut height = 0.0f32;

            for child in &mut self.children {
                child.layout(containing_block);
                width += child.dimensions.margin_box().width;
                height = height.max(child.dimensions.margin_box().height);
            }

            self.dimensions.content.width = width;
            self.dimensions.content.height = height;
        }

        // 位置を設定
        self.dimensions.content.x = containing_block.content.x;
        self.dimensions.content.y = containing_block.content.y + containing_block.content.height;
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rect() {
        let rect = Rect::new(10.0, 20.0, 100.0, 50.0);
        assert_eq!(rect.right(), 110.0);
        assert_eq!(rect.bottom(), 70.0);
    }

    #[test]
    fn test_dimensions() {
        let mut d = Dimensions::default();
        d.content = Rect::new(0.0, 0.0, 100.0, 50.0);
        d.padding = EdgeSizes::uniform(10.0);
        d.border = EdgeSizes::uniform(1.0);
        d.margin = EdgeSizes::uniform(5.0);

        let border_box = d.border_box();
        assert_eq!(border_box.width, 122.0); // 100 + 10*2 + 1*2
        assert_eq!(border_box.height, 72.0); // 50 + 10*2 + 1*2
    }
}
