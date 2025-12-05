// ============================================================================
// src/application/games/solitaire.rs - Solitaire (Klondike) Game
// ============================================================================
//!
//! # ソリティア（クロンダイク）
//!
//! ウィンドウシステムのドラッグ＆ドロップ機能のデモとして実装。
//!
//! ## 機能
//! - 52枚のカードデッキ
//! - ドラッグ＆ドロップによるカード移動
//! - クロンダイクルール（タブロー、組札、山札）
//! - 自動完了機能

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::format;

use crate::graphics::{Color, image::Image, Rect, Point};

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
const TABLEAU_START_X: u32 = 20;
/// タブローの開始Y座標
const TABLEAU_START_Y: u32 = 130;
/// タブロー間の隙間
const TABLEAU_GAP: u32 = 10;

/// 組札の開始X座標
const FOUNDATION_START_X: u32 = 280;
/// 組札のY座標
const FOUNDATION_Y: u32 = 20;

/// 山札のX座標
const STOCK_X: u32 = 20;
/// 山札のY座標
const STOCK_Y: u32 = 20;
/// 捨て札のX座標
const WASTE_X: u32 = 110;

// ============================================================================
// Colors
// ============================================================================

/// 背景色（緑のフェルト）
const BG_COLOR: Color = Color { red: 0, green: 100, blue: 50, alpha: 255 };
/// カードの白
const CARD_WHITE: Color = Color { red: 255, green: 255, blue: 255, alpha: 255 };
/// カードの裏面
const CARD_BACK: Color = Color { red: 0, green: 0, blue: 180, alpha: 255 };
/// カードの枠
const CARD_BORDER: Color = Color { red: 80, green: 80, blue: 80, alpha: 255 };
/// 赤いスート
const SUIT_RED: Color = Color { red: 200, green: 0, blue: 0, alpha: 255 };
/// 黒いスート
const SUIT_BLACK: Color = Color { red: 0, green: 0, blue: 0, alpha: 255 };
/// 空のスロット
const EMPTY_SLOT: Color = Color { red: 0, green: 80, blue: 40, alpha: 255 };
/// 選択されたカード
const SELECTED_COLOR: Color = Color { red: 255, green: 255, blue: 0, alpha: 255 };

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
// Solitaire Game - 構造体定義
// ============================================================================

/// ソリティアゲーム
pub struct Solitaire {
    /// 山札
    stock: Vec<Card>,
    /// 捨て札
    waste: Vec<Card>,
    /// タブロー（7列）
    tableau: [Vec<Card>; 7],
    /// 組札（4つ）
    foundation: [Vec<Card>; 4],
    /// ゲーム状態
    state: GameState,
    /// ドラッグ状態
    drag: Option<DragState>,
    /// 移動回数
    moves: u32,
    /// 乱数シード
    rng_seed: u64,
}

impl Solitaire {
    /// 新しいゲームを作成
    pub fn new() -> Self {
        let mut game = Self {
            stock: Vec::new(),
            waste: Vec::new(),
            tableau: Default::default(),
            foundation: Default::default(),
            state: GameState::Playing,
            drag: None,
            moves: 0,
            rng_seed: 12345,
        };
        game.deal();
        game
    }

    /// 乱数生成
    fn rand(&mut self) -> u64 {
        self.rng_seed = self.rng_seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.rng_seed
    }

    /// カードをシャッフル
    fn shuffle(&mut self, cards: &mut Vec<Card>) {
        let n = cards.len();
        for i in (1..n).rev() {
            let j = (self.rand() % (i as u64 + 1)) as usize;
            cards.swap(i, j);
        }
    }

    /// カードを配る
    fn deal(&mut self) {
        // デッキを作成
        let mut deck = Vec::with_capacity(52);
        for suit_idx in 0..4 {
            if let Some(suit) = Suit::from_index(suit_idx) {
                for rank_idx in 1..=13 {
                    if let Some(rank) = Rank::from_index(rank_idx) {
                        deck.push(Card::new(suit, rank));
                    }
                }
            }
        }

        // シャッフル
        self.shuffle(&mut deck);

        // タブローに配る
        for i in 0..7 {
            self.tableau[i].clear();
            for j in 0..=i {
                if let Some(mut card) = deck.pop() {
                    if j == i {
                        card.face_up = true;
                    }
                    self.tableau[i].push(card);
                }
            }
        }

        // 残りは山札へ
        self.stock = deck;
        self.waste.clear();
        for i in 0..4 {
            self.foundation[i].clear();
        }

        self.state = GameState::Playing;
        self.moves = 0;
    }

    /// ゲームをリセット
    pub fn reset(&mut self) {
        self.deal();
    }

    /// ゲーム状態を取得
    pub fn state(&self) -> GameState {
        self.state
    }

    /// 移動回数を取得
    pub fn moves(&self) -> u32 {
        self.moves
    }

    /// ウィンドウの幅を取得
    pub fn window_width(&self) -> u32 {
        FIELD_WIDTH
    }

    /// ウィンドウの高さを取得
    pub fn window_height(&self) -> u32 {
        FIELD_HEIGHT
    }
}

impl Default for Solitaire {
    fn default() -> Self {
        Self::new()
    }
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

// ============================================================================
// Solitaire Game - ゲームロジック
// ============================================================================

impl Solitaire {
    // ========================================================================
    // カード移動ロジック
    // ========================================================================

    /// 山札をクリック
    fn click_stock(&mut self) {
        if self.stock.is_empty() {
            // 捨て札を山札に戻す
            while let Some(mut card) = self.waste.pop() {
                card.face_up = false;
                self.stock.push(card);
            }
        } else {
            // 山札から捨て札へ
            if let Some(mut card) = self.stock.pop() {
                card.face_up = true;
                self.waste.push(card);
            }
        }
    }

    /// タブローの一番上のカードを表にする
    fn flip_top_tableau(&mut self, col: usize) {
        if let Some(card) = self.tableau[col].last_mut() {
            if !card.face_up {
                card.face_up = true;
            }
        }
    }

    /// カードをタブローに移動できるか
    fn can_move_to_tableau(&self, card: &Card, col: usize) -> bool {
        if let Some(top) = self.tableau[col].last() {
            card.can_place_on_tableau(top)
        } else {
            // 空のタブローにはKingのみ
            card.rank == Rank::King
        }
    }

    /// カードを組札に移動できるか
    fn can_move_to_foundation(&self, card: &Card, foundation_idx: usize) -> bool {
        let suit = match Suit::from_index(foundation_idx as u8) {
            Some(s) => s,
            None => return false,
        };
        let top = self.foundation[foundation_idx].last();
        card.can_place_on_foundation(top, suit)
    }

    /// 捨て札からカードを移動
    fn move_from_waste(&mut self, target: CardLocation) -> bool {
        let card = match self.waste.last() {
            Some(c) => *c,
            None => return false,
        };

        match target {
            CardLocation::Tableau(col) => {
                if self.can_move_to_tableau(&card, col) {
                    self.waste.pop();
                    self.tableau[col].push(card);
                    self.moves += 1;
                    return true;
                }
            }
            CardLocation::Foundation(idx) => {
                if self.can_move_to_foundation(&card, idx) {
                    self.waste.pop();
                    self.foundation[idx].push(card);
                    self.moves += 1;
                    self.check_win();
                    return true;
                }
            }
            _ => {}
        }
        false
    }

    /// タブローからカードを移動
    fn move_from_tableau(&mut self, src_col: usize, card_idx: usize, target: CardLocation) -> bool {
        if card_idx >= self.tableau[src_col].len() {
            return false;
        }

        // 移動するカードを取得
        let cards: Vec<Card> = self.tableau[src_col][card_idx..].to_vec();
        if cards.is_empty() {
            return false;
        }

        let first_card = cards[0];

        match target {
            CardLocation::Tableau(dst_col) => {
                if src_col == dst_col {
                    return false;
                }
                if self.can_move_to_tableau(&first_card, dst_col) {
                    // カードを移動
                    self.tableau[src_col].truncate(card_idx);
                    self.tableau[dst_col].extend(cards);
                    self.flip_top_tableau(src_col);
                    self.moves += 1;
                    return true;
                }
            }
            CardLocation::Foundation(idx) => {
                // 組札には1枚のみ移動可能
                if cards.len() == 1 && self.can_move_to_foundation(&first_card, idx) {
                    self.tableau[src_col].pop();
                    self.foundation[idx].push(first_card);
                    self.flip_top_tableau(src_col);
                    self.moves += 1;
                    self.check_win();
                    return true;
                }
            }
            _ => {}
        }
        false
    }

    /// 勝利判定
    fn check_win(&mut self) {
        let total: usize = self.foundation.iter().map(|f| f.len()).sum();
        if total == 52 {
            self.state = GameState::Won;
        }
    }

    /// 自動で組札に移動できるカードを移動
    pub fn auto_move_to_foundation(&mut self) -> bool {
        // 捨て札から
        if let Some(card) = self.waste.last() {
            for i in 0..4 {
                if self.can_move_to_foundation(card, i) {
                    return self.move_from_waste(CardLocation::Foundation(i));
                }
            }
        }

        // タブローから
        for col in 0..7 {
            if let Some(card) = self.tableau[col].last() {
                if card.face_up {
                    for i in 0..4 {
                        if self.can_move_to_foundation(card, i) {
                            let idx = self.tableau[col].len() - 1;
                            return self.move_from_tableau(col, idx, CardLocation::Foundation(i));
                        }
                    }
                }
            }
        }

        false
    }

    // ========================================================================
    // 座標計算
    // ========================================================================

    /// タブロー列のX座標
    fn tableau_x(&self, col: usize) -> u32 {
        TABLEAU_START_X + col as u32 * (CARD_WIDTH + TABLEAU_GAP)
    }

    /// タブロー内のカードのY座標
    fn tableau_card_y(&self, col: usize, card_idx: usize) -> u32 {
        let mut y = TABLEAU_START_Y;
        for i in 0..card_idx {
            if i < self.tableau[col].len() {
                if self.tableau[col][i].face_up {
                    y += CARD_OVERLAP_FACE_UP;
                } else {
                    y += CARD_OVERLAP_FACE_DOWN;
                }
            }
        }
        y
    }

    /// 組札のX座標
    fn foundation_x(&self, idx: usize) -> u32 {
        FOUNDATION_START_X + idx as u32 * (CARD_WIDTH + TABLEAU_GAP)
    }

    /// 座標からカードの場所を取得
    fn location_at(&self, x: i32, y: i32) -> Option<(CardLocation, usize)> {
        // 山札
        if x >= STOCK_X as i32
            && x < (STOCK_X + CARD_WIDTH) as i32
            && y >= STOCK_Y as i32
            && y < (STOCK_Y + CARD_HEIGHT) as i32
        {
            return Some((CardLocation::Stock, 0));
        }

        // 捨て札
        if x >= WASTE_X as i32
            && x < (WASTE_X + CARD_WIDTH) as i32
            && y >= STOCK_Y as i32
            && y < (STOCK_Y + CARD_HEIGHT) as i32
        {
            if !self.waste.is_empty() {
                return Some((CardLocation::Waste, self.waste.len() - 1));
            }
        }

        // 組札
        for i in 0..4 {
            let fx = self.foundation_x(i) as i32;
            if x >= fx
                && x < fx + CARD_WIDTH as i32
                && y >= FOUNDATION_Y as i32
                && y < (FOUNDATION_Y + CARD_HEIGHT) as i32
            {
                return Some((CardLocation::Foundation(i), 
                    self.foundation[i].len().saturating_sub(1)));
            }
        }

        // タブロー
        for col in 0..7 {
            let tx = self.tableau_x(col) as i32;
            if x >= tx && x < tx + CARD_WIDTH as i32 {
                // Y座標からカードを特定（下から上へ）
                for card_idx in (0..self.tableau[col].len()).rev() {
                    let cy = self.tableau_card_y(col, card_idx) as i32;
                    let ch = if card_idx == self.tableau[col].len() - 1 {
                        CARD_HEIGHT
                    } else if self.tableau[col][card_idx].face_up {
                        CARD_OVERLAP_FACE_UP
                    } else {
                        CARD_OVERLAP_FACE_DOWN
                    };

                    if y >= cy && y < cy + ch as i32 {
                        return Some((CardLocation::Tableau(col), card_idx));
                    }
                }
                // 空のタブロー
                if self.tableau[col].is_empty()
                    && y >= TABLEAU_START_Y as i32
                    && y < (TABLEAU_START_Y + CARD_HEIGHT) as i32
                {
                    return Some((CardLocation::Tableau(col), 0));
                }
            }
        }

        None
    }
}

// ============================================================================
// Solitaire Game - マウスイベント
// ============================================================================

impl Solitaire {
    /// マウスボタン押下
    pub fn on_mouse_down(&mut self, x: u32, y: u32) {
        if self.state == GameState::Won {
            return;
        }

        let loc = self.location_at(x as i32, y as i32);

        match loc {
            Some((CardLocation::Stock, _)) => {
                self.click_stock();
            }
            Some((CardLocation::Waste, _)) => {
                // 捨て札からドラッグ開始
                if let Some(card) = self.waste.last().cloned() {
                    self.drag = Some(DragState {
                        cards: vec![card],
                        source: CardLocation::Waste,
                        x: x as i32,
                        y: y as i32,
                        offset_x: x as i32 - WASTE_X as i32,
                        offset_y: y as i32 - STOCK_Y as i32,
                    });
                }
            }
            Some((CardLocation::Tableau(col), card_idx)) => {
                // タブローからドラッグ開始
                if card_idx < self.tableau[col].len() 
                    && self.tableau[col][card_idx].face_up 
                {
                    let cards: Vec<Card> = self.tableau[col][card_idx..].to_vec();
                    let card_y = self.tableau_card_y(col, card_idx);
                    self.drag = Some(DragState {
                        cards,
                        source: CardLocation::Tableau(col),
                        x: x as i32,
                        y: y as i32,
                        offset_x: x as i32 - self.tableau_x(col) as i32,
                        offset_y: y as i32 - card_y as i32,
                    });
                }
            }
            Some((CardLocation::Foundation(idx), _)) => {
                // 組札からドラッグ（上級者向け）
                if let Some(card) = self.foundation[idx].last().cloned() {
                    self.drag = Some(DragState {
                        cards: vec![card],
                        source: CardLocation::Foundation(idx),
                        x: x as i32,
                        y: y as i32,
                        offset_x: x as i32 - self.foundation_x(idx) as i32,
                        offset_y: y as i32 - FOUNDATION_Y as i32,
                    });
                }
            }
            None => {}
        }
    }

    /// マウス移動
    pub fn on_mouse_move(&mut self, x: u32, y: u32) {
        if let Some(ref mut drag) = self.drag {
            drag.x = x as i32;
            drag.y = y as i32;
        }
    }

    /// マウスボタン解放
    pub fn on_mouse_up(&mut self, x: u32, y: u32) {
        let drag = match self.drag.take() {
            Some(d) => d,
            None => return,
        };

        if drag.cards.is_empty() {
            return;
        }

        // ドロップ先を検出
        let target = self.location_at(x as i32, y as i32);

        let moved = match (drag.source, target) {
            (CardLocation::Waste, Some((target_loc, _))) => {
                self.move_from_waste(target_loc)
            }
            (CardLocation::Tableau(src_col), Some((target_loc, _))) => {
                let card_idx = self.tableau[src_col].len()
                    .saturating_sub(drag.cards.len());
                self.move_from_tableau(src_col, card_idx, target_loc)
            }
            (CardLocation::Foundation(idx), Some((CardLocation::Tableau(col), _))) => {
                // 組札からタブローへ
                if let Some(card) = self.foundation[idx].last().cloned() {
                    if self.can_move_to_tableau(&card, col) {
                        self.foundation[idx].pop();
                        self.tableau[col].push(card);
                        self.moves += 1;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            _ => false,
        };

        if !moved {
            // 元の場所に戻す（何もしない - カードはまだそこにある）
        }
    }

    /// ダブルクリック
    pub fn on_double_click(&mut self, x: u32, y: u32) {
        if self.state == GameState::Won {
            self.reset();
            return;
        }

        // ダブルクリックで自動的に組札へ移動
        let loc = self.location_at(x as i32, y as i32);

        match loc {
            Some((CardLocation::Waste, _)) => {
                if let Some(card) = self.waste.last().cloned() {
                    for i in 0..4 {
                        if self.can_move_to_foundation(&card, i) {
                            self.move_from_waste(CardLocation::Foundation(i));
                            break;
                        }
                    }
                }
            }
            Some((CardLocation::Tableau(col), card_idx)) => {
                if card_idx == self.tableau[col].len().saturating_sub(1) {
                    if let Some(card) = self.tableau[col].last().cloned() {
                        for i in 0..4 {
                            if self.can_move_to_foundation(&card, i) {
                                self.move_from_tableau(col, card_idx, CardLocation::Foundation(i));
                                break;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

// ============================================================================
// Solitaire Game - レンダリング
// ============================================================================

impl Solitaire {
    /// 描画
    pub fn render(&self, image: &mut Image) {
        // 背景
        self.fill_rect(image, 0, 0, FIELD_WIDTH, FIELD_HEIGHT, BG_COLOR);

        // 山札
        self.render_stock(image);

        // 捨て札
        self.render_waste(image);

        // 組札
        self.render_foundations(image);

        // タブロー
        self.render_tableau(image);

        // ドラッグ中のカード
        self.render_drag(image);

        // ヘッダー（移動回数）
        self.render_header(image);

        // 勝利メッセージ
        if self.state == GameState::Won {
            self.render_win_message(image);
        }
    }

    /// 山札を描画
    fn render_stock(&self, image: &mut Image) {
        if self.stock.is_empty() {
            // 空のスロット（クリックで戻す）
            self.draw_empty_slot(image, STOCK_X, STOCK_Y);
            // リサイクルマーク
            self.draw_recycle_icon(image, STOCK_X, STOCK_Y);
        } else {
            // カードの裏面
            self.draw_card_back(image, STOCK_X, STOCK_Y);
        }
    }

    /// 捨て札を描画
    fn render_waste(&self, image: &mut Image) {
        if let Some(card) = self.waste.last() {
            let is_dragging = self.drag.as_ref()
                .map(|d| d.source == CardLocation::Waste)
                .unwrap_or(false);
            if !is_dragging {
                self.draw_card(image, WASTE_X, STOCK_Y, card);
            }
        }
    }

    /// 組札を描画
    fn render_foundations(&self, image: &mut Image) {
        for i in 0..4 {
            let x = self.foundation_x(i);
            let is_dragging = self.drag.as_ref()
                .map(|d| d.source == CardLocation::Foundation(i))
                .unwrap_or(false);

            if let Some(card) = self.foundation[i].last() {
                if !is_dragging {
                    self.draw_card(image, x, FOUNDATION_Y, card);
                } else if self.foundation[i].len() > 1 {
                    // ドラッグ中は下のカードを表示
                    let below = &self.foundation[i][self.foundation[i].len() - 2];
                    self.draw_card(image, x, FOUNDATION_Y, below);
                } else {
                    self.draw_empty_slot(image, x, FOUNDATION_Y);
                    self.draw_suit_icon(image, x, FOUNDATION_Y, i);
                }
            } else {
                self.draw_empty_slot(image, x, FOUNDATION_Y);
                self.draw_suit_icon(image, x, FOUNDATION_Y, i);
            }
        }
    }

    /// タブローを描画
    fn render_tableau(&self, image: &mut Image) {
        for col in 0..7 {
            let x = self.tableau_x(col);

            if self.tableau[col].is_empty() {
                self.draw_empty_slot(image, x, TABLEAU_START_Y);
                continue;
            }

            // ドラッグ中のカード数を取得
            let drag_count = self.drag.as_ref()
                .filter(|d| d.source == CardLocation::Tableau(col))
                .map(|d| d.cards.len())
                .unwrap_or(0);

            let visible_count = self.tableau[col].len().saturating_sub(drag_count);

            for (i, card) in self.tableau[col].iter().take(visible_count).enumerate() {
                let y = self.tableau_card_y(col, i);
                if card.face_up {
                    self.draw_card(image, x, y, card);
                } else {
                    self.draw_card_back(image, x, y);
                }
            }
        }
    }

    /// ドラッグ中のカードを描画
    fn render_drag(&self, image: &mut Image) {
        if let Some(ref drag) = self.drag {
            let base_x = drag.x - drag.offset_x;
            let base_y = drag.y - drag.offset_y;

            for (i, card) in drag.cards.iter().enumerate() {
                let y = base_y + (i as i32 * CARD_OVERLAP_FACE_UP as i32);
                self.draw_card(image, base_x as u32, y as u32, card);
            }
        }
    }

    /// ヘッダーを描画
    fn render_header(&self, image: &mut Image) {
        let moves_text = format!("Moves: {}", self.moves);
        self.draw_text(image, &moves_text, 200, 10, CARD_WHITE);
    }

    /// 勝利メッセージを描画
    fn render_win_message(&self, image: &mut Image) {
        let box_w = 200u32;
        let box_h = 60u32;
        let box_x = (FIELD_WIDTH - box_w) / 2;
        let box_y = (FIELD_HEIGHT - box_h) / 2;

        // 背景
        self.fill_rect(image, box_x, box_y, box_w, box_h, 
            Color { red: 0, green: 0, blue: 0, alpha: 200 });

        // 枠
        for dx in 0..box_w {
            image.set_pixel(box_x + dx, box_y, CARD_WHITE);
            image.set_pixel(box_x + dx, box_y + box_h - 1, CARD_WHITE);
        }
        for dy in 0..box_h {
            image.set_pixel(box_x, box_y + dy, CARD_WHITE);
            image.set_pixel(box_x + box_w - 1, box_y + dy, CARD_WHITE);
        }

        self.draw_text(image, "YOU WIN!", box_x + 70, box_y + 15, CARD_WHITE);
        let moves_text = format!("Moves: {}", self.moves);
        self.draw_text(image, &moves_text, box_x + 70, box_y + 35, CARD_WHITE);
    }

    // ========================================================================
    // カード描画
    // ========================================================================

    /// カードを描画
    fn draw_card(&self, image: &mut Image, x: u32, y: u32, card: &Card) {
        // カードの背景
        self.fill_rect(image, x, y, CARD_WIDTH, CARD_HEIGHT, CARD_WHITE);

        // 枠線
        for dx in 0..CARD_WIDTH {
            image.set_pixel(x + dx, y, CARD_BORDER);
            image.set_pixel(x + dx, y + CARD_HEIGHT - 1, CARD_BORDER);
        }
        for dy in 0..CARD_HEIGHT {
            image.set_pixel(x, y + dy, CARD_BORDER);
            image.set_pixel(x + CARD_WIDTH - 1, y + dy, CARD_BORDER);
        }

        // 角を丸くする
        image.set_pixel(x, y, BG_COLOR);
        image.set_pixel(x + CARD_WIDTH - 1, y, BG_COLOR);
        image.set_pixel(x, y + CARD_HEIGHT - 1, BG_COLOR);
        image.set_pixel(x + CARD_WIDTH - 1, y + CARD_HEIGHT - 1, BG_COLOR);

        // ランクとスート
        let color = card.suit.color();
        let rank_str = card.rank.symbol();
        let suit_char = card.suit.symbol();

        // 左上にランク
        self.draw_text(image, rank_str, x + 4, y + 4, color);

        // 左上にスート
        self.draw_text(image, &alloc::string::String::from(suit_char), x + 4, y + 14, color);

        // 中央にスート（大きく）
        self.draw_large_suit(image, x + CARD_WIDTH / 2 - 10, y + CARD_HEIGHT / 2 - 10, card.suit);

        // 右下にランク（逆さ）
        self.draw_text(image, rank_str, x + CARD_WIDTH - 14, y + CARD_HEIGHT - 14, color);
    }

    /// カードの裏面を描画
    fn draw_card_back(&self, image: &mut Image, x: u32, y: u32) {
        // 青い背景
        self.fill_rect(image, x, y, CARD_WIDTH, CARD_HEIGHT, CARD_BACK);

        // 枠線
        for dx in 0..CARD_WIDTH {
            image.set_pixel(x + dx, y, CARD_BORDER);
            image.set_pixel(x + dx, y + CARD_HEIGHT - 1, CARD_BORDER);
        }
        for dy in 0..CARD_HEIGHT {
            image.set_pixel(x, y + dy, CARD_BORDER);
            image.set_pixel(x + CARD_WIDTH - 1, y + dy, CARD_BORDER);
        }

        // 角を丸くする
        image.set_pixel(x, y, BG_COLOR);
        image.set_pixel(x + CARD_WIDTH - 1, y, BG_COLOR);
        image.set_pixel(x, y + CARD_HEIGHT - 1, BG_COLOR);
        image.set_pixel(x + CARD_WIDTH - 1, y + CARD_HEIGHT - 1, BG_COLOR);

        // 模様（格子）
        let pattern_color = Color { red: 0, green: 0, blue: 140, alpha: 255 };
        for dy in (4..CARD_HEIGHT - 4).step_by(6) {
            for dx in (4..CARD_WIDTH - 4).step_by(6) {
                if (dx / 6 + dy / 6) % 2 == 0 {
                    self.fill_rect(image, x + dx, y + dy, 4, 4, pattern_color);
                }
            }
        }
    }

    /// 空のスロットを描画
    fn draw_empty_slot(&self, image: &mut Image, x: u32, y: u32) {
        self.fill_rect(image, x, y, CARD_WIDTH, CARD_HEIGHT, EMPTY_SLOT);

        // 枠線（点線風）
        for dx in (0..CARD_WIDTH).step_by(4) {
            image.set_pixel(x + dx, y, CARD_BORDER);
            image.set_pixel(x + dx, y + CARD_HEIGHT - 1, CARD_BORDER);
        }
        for dy in (0..CARD_HEIGHT).step_by(4) {
            image.set_pixel(x, y + dy, CARD_BORDER);
            image.set_pixel(x + CARD_WIDTH - 1, y + dy, CARD_BORDER);
        }
    }

    /// リサイクルアイコンを描画
    fn draw_recycle_icon(&self, image: &mut Image, x: u32, y: u32) {
        let cx = x + CARD_WIDTH / 2;
        let cy = y + CARD_HEIGHT / 2;
        let r = 15u32;
        let color = Color { red: 100, green: 150, blue: 100, alpha: 255 };

        // 簡易的な円形矢印
        for angle in 0..360 {
            let rad = (angle as f32) * 3.14159 / 180.0;
            let px = cx as i32 + (r as f32 * rad.cos()) as i32;
            let py = cy as i32 + (r as f32 * rad.sin()) as i32;
            if px >= 0 && py >= 0 {
                image.set_pixel(px as u32, py as u32, color);
            }
        }
    }

    /// スートアイコンを描画
    fn draw_suit_icon(&self, image: &mut Image, x: u32, y: u32, suit_idx: usize) {
        if let Some(suit) = Suit::from_index(suit_idx as u8) {
            let cx = x + CARD_WIDTH / 2;
            let cy = y + CARD_HEIGHT / 2;
            let color = Color { red: 60, green: 100, blue: 60, alpha: 255 };
            self.draw_text(image, &alloc::string::String::from(suit.symbol()), cx - 4, cy - 4, color);
        }
    }

    /// 大きなスートを描画
    fn draw_large_suit(&self, image: &mut Image, x: u32, y: u32, suit: Suit) {
        let color = suit.color();
        
        match suit {
            Suit::Hearts => {
                // ハート
                for dy in 0..20u32 {
                    for dx in 0..20u32 {
                        let fx = dx as f32 / 10.0 - 1.0;
                        let fy = dy as f32 / 10.0 - 1.0;
                        let heart = (fx * fx + fy * fy - 1.0).powi(3) - fx * fx * fy.powi(3);
                        if heart < 0.0 {
                            image.set_pixel(x + dx, y + dy, color);
                        }
                    }
                }
            }
            Suit::Diamonds => {
                // ダイヤ
                for dy in 0..20u32 {
                    for dx in 0..20u32 {
                        let cx = 10i32;
                        let cy = 10i32;
                        let dist = (dx as i32 - cx).abs() + (dy as i32 - cy).abs();
                        if dist < 10 {
                            image.set_pixel(x + dx, y + dy, color);
                        }
                    }
                }
            }
            Suit::Clubs => {
                // クラブ（3つの円と茎）
                self.fill_circle(image, x + 10, y + 6, 5, color);
                self.fill_circle(image, x + 5, y + 12, 5, color);
                self.fill_circle(image, x + 15, y + 12, 5, color);
                self.fill_rect(image, x + 8, y + 14, 4, 6, color);
            }
            Suit::Spades => {
                // スペード（逆ハート+茎）
                for dy in 0..14u32 {
                    for dx in 0..20u32 {
                        let fx = dx as f32 / 10.0 - 1.0;
                        let fy = 1.0 - dy as f32 / 7.0;
                        let heart = (fx * fx + fy * fy - 1.0).powi(3) - fx * fx * fy.powi(3);
                        if heart < 0.0 {
                            image.set_pixel(x + dx, y + dy, color);
                        }
                    }
                }
                self.fill_rect(image, x + 8, y + 12, 4, 8, color);
            }
        }
    }

    /// 円を塗りつぶす
    fn fill_circle(&self, image: &mut Image, cx: u32, cy: u32, r: u32, color: Color) {
        let r_sq = (r * r) as i32;
        for dy in 0..r * 2 {
            for dx in 0..r * 2 {
                let px = dx as i32 - r as i32;
                let py = dy as i32 - r as i32;
                if px * px + py * py <= r_sq {
                    let x = cx + dx - r;
                    let y = cy + dy - r;
                    if x < image.width() && y < image.height() {
                        image.set_pixel(x, y, color);
                    }
                }
            }
        }
    }

    // ========================================================================
    // 描画ユーティリティ
    // ========================================================================

    /// 矩形を塗りつぶす
    fn fill_rect(&self, image: &mut Image, x: u32, y: u32, w: u32, h: u32, color: Color) {
        for dy in 0..h {
            for dx in 0..w {
                if x + dx < image.width() && y + dy < image.height() {
                    image.set_pixel(x + dx, y + dy, color);
                }
            }
        }
    }

    /// 簡易テキスト描画
    fn draw_text(&self, image: &mut Image, text: &str, x: u32, y: u32, color: Color) {
        static FONT_4X6: [[u8; 6]; 95] = [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0], // Space
            [0x4, 0x4, 0x4, 0x0, 0x4, 0x0], // !
            [0xA, 0xA, 0x0, 0x0, 0x0, 0x0], // "
            [0xA, 0xF, 0xA, 0xF, 0xA, 0x0], // #
            [0x4, 0xE, 0xC, 0x6, 0xE, 0x4], // $
            [0x9, 0x2, 0x4, 0x8, 0x9, 0x0], // %
            [0x4, 0xA, 0x4, 0xA, 0x5, 0x0], // &
            [0x4, 0x4, 0x0, 0x0, 0x0, 0x0], // '
            [0x2, 0x4, 0x4, 0x4, 0x2, 0x0], // (
            [0x4, 0x2, 0x2, 0x2, 0x4, 0x0], // )
            [0x0, 0xA, 0x4, 0xA, 0x0, 0x0], // *
            [0x0, 0x4, 0xE, 0x4, 0x0, 0x0], // +
            [0x0, 0x0, 0x0, 0x4, 0x4, 0x8], // ,
            [0x0, 0x0, 0xE, 0x0, 0x0, 0x0], // -
            [0x0, 0x0, 0x0, 0x0, 0x4, 0x0], // .
            [0x1, 0x2, 0x4, 0x8, 0x8, 0x0], // /
            [0x6, 0x9, 0x9, 0x9, 0x6, 0x0], // 0
            [0x4, 0xC, 0x4, 0x4, 0xE, 0x0], // 1
            [0x6, 0x9, 0x2, 0x4, 0xF, 0x0], // 2
            [0xE, 0x1, 0x6, 0x1, 0xE, 0x0], // 3
            [0x2, 0x6, 0xA, 0xF, 0x2, 0x0], // 4
            [0xF, 0x8, 0xE, 0x1, 0xE, 0x0], // 5
            [0x6, 0x8, 0xE, 0x9, 0x6, 0x0], // 6
            [0xF, 0x1, 0x2, 0x4, 0x4, 0x0], // 7
            [0x6, 0x9, 0x6, 0x9, 0x6, 0x0], // 8
            [0x6, 0x9, 0x7, 0x1, 0x6, 0x0], // 9
            [0x0, 0x4, 0x0, 0x4, 0x0, 0x0], // :
            [0x0, 0x4, 0x0, 0x4, 0x4, 0x8], // ;
            [0x1, 0x2, 0x4, 0x2, 0x1, 0x0], // <
            [0x0, 0xE, 0x0, 0xE, 0x0, 0x0], // =
            [0x4, 0x2, 0x1, 0x2, 0x4, 0x0], // >
            [0x6, 0x9, 0x2, 0x0, 0x2, 0x0], // ?
            [0x6, 0x9, 0xB, 0x8, 0x6, 0x0], // @
            [0x6, 0x9, 0xF, 0x9, 0x9, 0x0], // A
            [0xE, 0x9, 0xE, 0x9, 0xE, 0x0], // B
            [0x6, 0x9, 0x8, 0x9, 0x6, 0x0], // C
            [0xE, 0x9, 0x9, 0x9, 0xE, 0x0], // D
            [0xF, 0x8, 0xE, 0x8, 0xF, 0x0], // E
            [0xF, 0x8, 0xE, 0x8, 0x8, 0x0], // F
            [0x6, 0x8, 0xB, 0x9, 0x6, 0x0], // G
            [0x9, 0x9, 0xF, 0x9, 0x9, 0x0], // H
            [0xE, 0x4, 0x4, 0x4, 0xE, 0x0], // I
            [0x7, 0x2, 0x2, 0xA, 0x4, 0x0], // J
            [0x9, 0xA, 0xC, 0xA, 0x9, 0x0], // K
            [0x8, 0x8, 0x8, 0x8, 0xF, 0x0], // L
            [0x9, 0xF, 0xF, 0x9, 0x9, 0x0], // M
            [0x9, 0xD, 0xB, 0x9, 0x9, 0x0], // N
            [0x6, 0x9, 0x9, 0x9, 0x6, 0x0], // O
            [0xE, 0x9, 0xE, 0x8, 0x8, 0x0], // P
            [0x6, 0x9, 0x9, 0xA, 0x5, 0x0], // Q
            [0xE, 0x9, 0xE, 0xA, 0x9, 0x0], // R
            [0x6, 0x8, 0x6, 0x1, 0xE, 0x0], // S
            [0xE, 0x4, 0x4, 0x4, 0x4, 0x0], // T
            [0x9, 0x9, 0x9, 0x9, 0x6, 0x0], // U
            [0x9, 0x9, 0x9, 0x6, 0x6, 0x0], // V
            [0x9, 0x9, 0xF, 0xF, 0x9, 0x0], // W
            [0x9, 0x9, 0x6, 0x9, 0x9, 0x0], // X
            [0x9, 0x9, 0x6, 0x4, 0x4, 0x0], // Y
            [0xF, 0x1, 0x6, 0x8, 0xF, 0x0], // Z
            [0x6, 0x4, 0x4, 0x4, 0x6, 0x0], // [
            [0x8, 0x8, 0x4, 0x2, 0x1, 0x0], // \
            [0x6, 0x2, 0x2, 0x2, 0x6, 0x0], // ]
            [0x4, 0xA, 0x0, 0x0, 0x0, 0x0], // ^
            [0x0, 0x0, 0x0, 0x0, 0xF, 0x0], // _
            [0x4, 0x2, 0x0, 0x0, 0x0, 0x0], // `
            [0x0, 0x6, 0xA, 0xA, 0x5, 0x0], // a
            [0x8, 0xE, 0x9, 0x9, 0xE, 0x0], // b
            [0x0, 0x6, 0x8, 0x8, 0x6, 0x0], // c
            [0x1, 0x7, 0x9, 0x9, 0x7, 0x0], // d
            [0x0, 0x6, 0xF, 0x8, 0x6, 0x0], // e
            [0x2, 0x4, 0xE, 0x4, 0x4, 0x0], // f
            [0x0, 0x7, 0x9, 0x7, 0x1, 0x6], // g
            [0x8, 0xE, 0x9, 0x9, 0x9, 0x0], // h
            [0x4, 0x0, 0x4, 0x4, 0x4, 0x0], // i
            [0x2, 0x0, 0x2, 0x2, 0xA, 0x4], // j
            [0x8, 0xA, 0xC, 0xA, 0x9, 0x0], // k
            [0x4, 0x4, 0x4, 0x4, 0x2, 0x0], // l
            [0x0, 0xA, 0xF, 0x9, 0x9, 0x0], // m
            [0x0, 0xE, 0x9, 0x9, 0x9, 0x0], // n
            [0x0, 0x6, 0x9, 0x9, 0x6, 0x0], // o
            [0x0, 0xE, 0x9, 0xE, 0x8, 0x8], // p
            [0x0, 0x7, 0x9, 0x7, 0x1, 0x1], // q
            [0x0, 0xE, 0x9, 0x8, 0x8, 0x0], // r
            [0x0, 0x6, 0xC, 0x2, 0xC, 0x0], // s
            [0x4, 0xE, 0x4, 0x4, 0x2, 0x0], // t
            [0x0, 0x9, 0x9, 0x9, 0x6, 0x0], // u
            [0x0, 0x9, 0x9, 0x6, 0x6, 0x0], // v
            [0x0, 0x9, 0x9, 0xF, 0x6, 0x0], // w
            [0x0, 0x9, 0x6, 0x6, 0x9, 0x0], // x
            [0x0, 0x9, 0x9, 0x7, 0x1, 0x6], // y
            [0x0, 0xF, 0x2, 0x4, 0xF, 0x0], // z
            [0x2, 0x4, 0x8, 0x4, 0x2, 0x0], // {
            [0x4, 0x4, 0x4, 0x4, 0x4, 0x0], // |
            [0x8, 0x4, 0x2, 0x4, 0x8, 0x0], // }
            [0x0, 0x5, 0xA, 0x0, 0x0, 0x0], // ~
        ];

        let mut cx = x;
        for ch in text.chars() {
            let code = ch as u32;
            if code >= 0x20 && code <= 0x7E {
                let glyph = &FONT_4X6[(code - 0x20) as usize];
                for (row, &bits) in glyph.iter().enumerate() {
                    for col in 0..4 {
                        if (bits >> (3 - col)) & 1 == 1 {
                            let px = cx + col;
                            let py = y + row as u32;
                            if px < image.width() && py < image.height() {
                                image.set_pixel(px, py, color);
                            }
                        }
                    }
                }
            }
            cx += 5;
        }
    }
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
    fn test_new_game() {
        let game = Solitaire::new();
        assert_eq!(game.state, GameState::Playing);
        assert_eq!(game.moves, 0);

        // タブローの確認
        for (i, pile) in game.tableau.iter().enumerate() {
            assert_eq!(pile.len(), i + 1);
            // 最後のカードのみ表向き
            for (j, card) in pile.iter().enumerate() {
                assert_eq!(card.face_up, j == i);
            }
        }
    }

    #[test]
    fn test_suit_color() {
        assert!(Suit::Hearts.is_red());
        assert!(Suit::Diamonds.is_red());
        assert!(!Suit::Spades.is_red());
        assert!(!Suit::Clubs.is_red());
    }
}
