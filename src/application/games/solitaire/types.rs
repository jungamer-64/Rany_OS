// ============================================================================
// src/application/games/solitaire/types.rs - Type Definitions
// ============================================================================
//!
//! ソリティアゲームの型定義と定数

extern crate alloc;

use alloc::vec::Vec;
use crate::graphics::Color;

// ============================================================================
// no_std Math Functions
// ============================================================================

/// 簡易的なsin関数（Taylor展開による近似）
pub fn sin_approx(x: f32) -> f32 {
    const PI: f32 = 3.14159265;
    let mut x = x % (2.0 * PI);
    if x > PI { x -= 2.0 * PI; }
    if x < -PI { x += 2.0 * PI; }
    let x2 = x * x;
    let x3 = x2 * x;
    let x5 = x3 * x2;
    x - x3 / 6.0 + x5 / 120.0
}

/// 簡易的なcos関数
pub fn cos_approx(x: f32) -> f32 {
    sin_approx(x + 3.14159265 / 2.0)
}

/// 簡易的なsqrt関数（Newton法）
#[allow(dead_code)]
pub fn sqrt_approx(x: f32) -> f32 {
    if x <= 0.0 { return 0.0; }
    let mut guess = x / 2.0;
    for _ in 0..10 {
        guess = (guess + x / guess) / 2.0;
    }
    guess
}

// ============================================================================
// Constants
// ============================================================================

/// カードの幅
pub const CARD_WIDTH: u32 = 71;
/// カードの高さ
pub const CARD_HEIGHT: u32 = 96;
/// カードの重なり（表向き）
pub const CARD_OVERLAP_FACE_UP: u32 = 20;
/// カードの重なり（裏向き）
pub const CARD_OVERLAP_FACE_DOWN: u32 = 10;

/// ゲームフィールドの幅
pub const FIELD_WIDTH: u32 = 640;
/// ゲームフィールドの高さ
pub const FIELD_HEIGHT: u32 = 480;

/// タブローの開始X座標
pub const TABLEAU_START_X: u32 = 20;
/// タブローの開始Y座標
pub const TABLEAU_START_Y: u32 = 130;
/// タブロー間の隙間
pub const TABLEAU_GAP: u32 = 10;

/// 組札の開始X座標
pub const FOUNDATION_START_X: u32 = 280;
/// 組札のY座標
pub const FOUNDATION_Y: u32 = 20;

/// 山札のX座標
pub const STOCK_X: u32 = 20;
/// 山札のY座標
pub const STOCK_Y: u32 = 20;
/// 捨て札のX座標
pub const WASTE_X: u32 = 110;

// ============================================================================
// Colors
// ============================================================================

/// 背景色（緑のフェルト）
pub const BG_COLOR: Color = Color { red: 0, green: 100, blue: 50, alpha: 255 };
/// カードの白
pub const CARD_WHITE: Color = Color { red: 255, green: 255, blue: 255, alpha: 255 };
/// カードの裏面
pub const CARD_BACK: Color = Color { red: 0, green: 0, blue: 180, alpha: 255 };
/// カードの枠
pub const CARD_BORDER: Color = Color { red: 80, green: 80, blue: 80, alpha: 255 };
/// 赤いスート
pub const SUIT_RED: Color = Color { red: 200, green: 0, blue: 0, alpha: 255 };
/// 黒いスート
pub const SUIT_BLACK: Color = Color { red: 0, green: 0, blue: 0, alpha: 255 };
/// 空のスロット
pub const EMPTY_SLOT: Color = Color { red: 0, green: 80, blue: 40, alpha: 255 };
/// 選択されたカード
#[allow(dead_code)]
pub const SELECTED_COLOR: Color = Color { red: 255, green: 255, blue: 0, alpha: 255 };

// ============================================================================
// Card Types
// ============================================================================

/// スート（マーク）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Suit {
    /// スペード
    Spades = 0,
    /// ハート
    Hearts = 1,
    /// ダイヤ
    Diamonds = 2,
    /// クラブ
    Clubs = 3,
}

impl Suit {
    /// スートの色を取得
    pub fn color(&self) -> Color {
        match self {
            Suit::Hearts | Suit::Diamonds => SUIT_RED,
            Suit::Spades | Suit::Clubs => SUIT_BLACK,
        }
    }

    /// 赤いスートか
    pub fn is_red(&self) -> bool {
        matches!(self, Suit::Hearts | Suit::Diamonds)
    }

    /// スートの記号を取得
    pub fn symbol(&self) -> char {
        match self {
            Suit::Spades => 'S',   // ♠
            Suit::Hearts => 'H',   // ♥
            Suit::Diamonds => 'D', // ♦
            Suit::Clubs => 'C',    // ♣
        }
    }

    /// インデックスからスートを取得
    pub fn from_index(index: u8) -> Option<Self> {
        match index {
            0 => Some(Suit::Spades),
            1 => Some(Suit::Hearts),
            2 => Some(Suit::Diamonds),
            3 => Some(Suit::Clubs),
            _ => None,
        }
    }
}

/// カードのランク（数値）
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Rank {
    Ace = 1,
    Two = 2,
    Three = 3,
    Four = 4,
    Five = 5,
    Six = 6,
    Seven = 7,
    Eight = 8,
    Nine = 9,
    Ten = 10,
    Jack = 11,
    Queen = 12,
    King = 13,
}

impl Rank {
    /// ランクの表示文字を取得
    pub fn symbol(&self) -> &'static str {
        match self {
            Rank::Ace => "A",
            Rank::Two => "2",
            Rank::Three => "3",
            Rank::Four => "4",
            Rank::Five => "5",
            Rank::Six => "6",
            Rank::Seven => "7",
            Rank::Eight => "8",
            Rank::Nine => "9",
            Rank::Ten => "10",
            Rank::Jack => "J",
            Rank::Queen => "Q",
            Rank::King => "K",
        }
    }

    /// インデックスからランクを取得
    pub fn from_index(index: u8) -> Option<Self> {
        match index {
            1 => Some(Rank::Ace),
            2 => Some(Rank::Two),
            3 => Some(Rank::Three),
            4 => Some(Rank::Four),
            5 => Some(Rank::Five),
            6 => Some(Rank::Six),
            7 => Some(Rank::Seven),
            8 => Some(Rank::Eight),
            9 => Some(Rank::Nine),
            10 => Some(Rank::Ten),
            11 => Some(Rank::Jack),
            12 => Some(Rank::Queen),
            13 => Some(Rank::King),
            _ => None,
        }
    }

    /// 数値を取得
    pub fn value(&self) -> u8 {
        *self as u8
    }
}

/// カード
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Card {
    /// スート
    pub suit: Suit,
    /// ランク
    pub rank: Rank,
    /// 表向きか
    pub face_up: bool,
}

impl Card {
    /// 新しいカードを作成
    pub fn new(suit: Suit, rank: Rank) -> Self {
        Self {
            suit,
            rank,
            face_up: false,
        }
    }

    /// カードを裏返す
    pub fn flip(&mut self) {
        self.face_up = !self.face_up;
    }

    /// カードが別のカードの上に置けるか（タブロー）
    pub fn can_place_on_tableau(&self, other: &Card) -> bool {
        // 色が違い、ランクが1つ下
        self.suit.is_red() != other.suit.is_red()
            && self.rank.value() + 1 == other.rank.value()
    }

    /// カードが組札に置けるか
    pub fn can_place_on_foundation(&self, top: Option<&Card>, suit: Suit) -> bool {
        if self.suit != suit {
            return false;
        }
        match top {
            None => self.rank == Rank::Ace,
            Some(top_card) => self.rank.value() == top_card.rank.value() + 1,
        }
    }
}

// ============================================================================
// Game Types
// ============================================================================

/// ゲームの状態
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GameState {
    /// プレイ中
    Playing,
    /// クリア
    Won,
}

/// ドラッグ中の情報
#[derive(Clone, Debug)]
pub struct DragState {
    /// ドラッグ中のカード
    pub cards: Vec<Card>,
    /// 元の場所
    pub source: CardLocation,
    /// 現在のX座標
    pub x: i32,
    /// 現在のY座標
    pub y: i32,
    /// ドラッグ開始時のオフセットX
    pub offset_x: i32,
    /// ドラッグ開始時のオフセットY
    pub offset_y: i32,
}

impl Default for DragState {
    fn default() -> Self {
        Self {
            cards: Vec::new(),
            source: CardLocation::Stock,
            x: 0,
            y: 0,
            offset_x: 0,
            offset_y: 0,
        }
    }
}

/// カードの場所
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardLocation {
    /// 山札
    Stock,
    /// 捨て札
    Waste,
    /// タブロー（列番号）
    Tableau(usize),
    /// 組札（スート）
    Foundation(usize),
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_card_creation() {
        let card = Card::new(Suit::Hearts, Rank::Ace);
        assert_eq!(card.suit, Suit::Hearts);
        assert_eq!(card.rank, Rank::Ace);
        assert!(!card.face_up);
    }

    #[test]
    fn test_card_flip() {
        let mut card = Card::new(Suit::Spades, Rank::King);
        assert!(!card.face_up);
        card.flip();
        assert!(card.face_up);
        card.flip();
        assert!(!card.face_up);
    }

    #[test]
    fn test_can_place_on_tableau() {
        let red_queen = Card::new(Suit::Hearts, Rank::Queen);
        let black_king = Card::new(Suit::Spades, Rank::King);
        let black_queen = Card::new(Suit::Clubs, Rank::Queen);

        assert!(red_queen.can_place_on_tableau(&black_king));
        assert!(!black_queen.can_place_on_tableau(&black_king));
    }

    #[test]
    fn test_can_place_on_foundation() {
        let ace = Card::new(Suit::Hearts, Rank::Ace);
        let two = Card::new(Suit::Hearts, Rank::Two);
        let wrong_suit = Card::new(Suit::Spades, Rank::Ace);

        assert!(ace.can_place_on_foundation(None, Suit::Hearts));
        assert!(!wrong_suit.can_place_on_foundation(None, Suit::Hearts));
        assert!(two.can_place_on_foundation(Some(&ace), Suit::Hearts));
    }

    #[test]
    fn test_suit_color() {
        assert!(Suit::Hearts.is_red());
        assert!(Suit::Diamonds.is_red());
        assert!(!Suit::Spades.is_red());
        assert!(!Suit::Clubs.is_red());
    }
}
