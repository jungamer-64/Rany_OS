// ============================================================================
// src/graphics/image.rs - Image Processing and Loading
// ============================================================================
//!
//! # 画像処理
//!
//! BMP、PNG（簡易）、アイコン等の画像フォーマット対応。
//!
//! ## 機能
//! - BMPファイル読み込み
//! - PNG簡易デコード
//! - 画像リサイズ・変換
//! - アルファブレンディング

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::vec;
use core::convert::TryInto;

use super::{Color, PixelFormat, Framebuffer, Rect, Point};

// ============================================================================
// Math Helpers
// ============================================================================

/// 高速平方根計算（ニュートン法）
fn fast_sqrt(x: f32) -> f32 {
    if x <= 0.0 {
        return 0.0;
    }

    // 初期推定値（ビット操作による高速近似）
    let mut i = x.to_bits();
    i = 0x5f3759df - (i >> 1);
    let mut y = f32::from_bits(i);

    // ニュートン法で精度を上げる
    y = y * (1.5 - 0.5 * x * y * y);
    y = y * (1.5 - 0.5 * x * y * y);

    1.0 / y
}

// ============================================================================
// Image Types
// ============================================================================

/// 画像データ
#[derive(Clone)]
pub struct Image {
    /// ピクセルデータ（RGBA形式）
    data: Vec<u8>,
    /// 幅
    width: u32,
    /// 高さ
    height: u32,
}

impl Image {
    /// 空の画像を作成
    pub fn new(width: u32, height: u32) -> Self {
        let size = (width * height * 4) as usize;
        Self {
            data: vec![0u8; size],
            width,
            height,
        }
    }

    /// 単色で塗りつぶした画像を作成
    pub fn filled(width: u32, height: u32, color: Color) -> Self {
        let size = (width * height) as usize;
        let mut data = Vec::with_capacity(size * 4);

        for _ in 0..size {
            data.push(color.red);
            data.push(color.green);
            data.push(color.blue);
            data.push(color.alpha);
        }

        Self { data, width, height }
    }

    /// 幅を取得
    pub fn width(&self) -> u32 {
        self.width
    }

    /// 高さを取得
    pub fn height(&self) -> u32 {
        self.height
    }

    /// ピクセルデータを取得
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// ピクセルデータをミュータブルに取得
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// ピクセルを取得
    pub fn get_pixel(&self, x: u32, y: u32) -> Color {
        if x >= self.width || y >= self.height {
            return Color::TRANSPARENT;
        }

        let idx = ((y * self.width + x) * 4) as usize;
        Color {
            red: self.data[idx],
            green: self.data[idx + 1],
            blue: self.data[idx + 2],
            alpha: self.data[idx + 3],
        }
    }

    /// ピクセルを設定
    pub fn set_pixel(&mut self, x: u32, y: u32, color: Color) {
        if x >= self.width || y >= self.height {
            return;
        }

        let idx = ((y * self.width + x) * 4) as usize;
        self.data[idx] = color.red;
        self.data[idx + 1] = color.green;
        self.data[idx + 2] = color.blue;
        self.data[idx + 3] = color.alpha;
    }

    /// アルファブレンディングでピクセルを設定
    pub fn blend_pixel(&mut self, x: u32, y: u32, color: Color) {
        if x >= self.width || y >= self.height {
            return;
        }

        let bg = self.get_pixel(x, y);
        let blended = alpha_blend(bg, color);
        self.set_pixel(x, y, blended);
    }

    /// 領域を塗りつぶし
    pub fn fill_rect(&mut self, rect: Rect, color: Color) {
        for y in rect.y.max(0)..(rect.y + rect.height as i32).min(self.height as i32) {
            for x in rect.x.max(0)..(rect.x + rect.width as i32).min(self.width as i32) {
                self.set_pixel(x as u32, y as u32, color);
            }
        }
    }

    /// 別の画像を描画
    pub fn blit(&mut self, src: &Image, dst_x: i32, dst_y: i32) {
        for y in 0..src.height as i32 {
            let dst_py = dst_y + y;
            if dst_py < 0 || dst_py >= self.height as i32 {
                continue;
            }

            for x in 0..src.width as i32 {
                let dst_px = dst_x + x;
                if dst_px < 0 || dst_px >= self.width as i32 {
                    continue;
                }

                let color = src.get_pixel(x as u32, y as u32);
                if color.alpha > 0 {
                    self.blend_pixel(dst_px as u32, dst_py as u32, color);
                }
            }
        }
    }

    /// フレームバッファに描画
    pub fn draw_to_framebuffer(&self, fb: &mut Framebuffer, x: i32, y: i32) {
        for py in 0..self.height as i32 {
            for px in 0..self.width as i32 {
                let color = self.get_pixel(px as u32, py as u32);
                if color.alpha > 0 {
                    fb.set_pixel(x + px, y + py, color);
                }
            }
        }
    }

    /// リサイズ（最近傍補間）
    pub fn resize_nearest(&self, new_width: u32, new_height: u32) -> Image {
        let mut result = Image::new(new_width, new_height);

        for y in 0..new_height {
            for x in 0..new_width {
                let src_x = (x * self.width / new_width).min(self.width - 1);
                let src_y = (y * self.height / new_height).min(self.height - 1);
                let color = self.get_pixel(src_x, src_y);
                result.set_pixel(x, y, color);
            }
        }

        result
    }

    /// リサイズ（バイリニア補間）
    pub fn resize_bilinear(&self, new_width: u32, new_height: u32) -> Image {
        let mut result = Image::new(new_width, new_height);

        let x_ratio = (self.width as f32 - 1.0) / new_width as f32;
        let y_ratio = (self.height as f32 - 1.0) / new_height as f32;

        for y in 0..new_height {
            for x in 0..new_width {
                let src_x = x as f32 * x_ratio;
                let src_y = y as f32 * y_ratio;

                let x_floor = src_x as u32;
                let y_floor = src_y as u32;
                let x_ceil = (x_floor + 1).min(self.width - 1);
                let y_ceil = (y_floor + 1).min(self.height - 1);

                let x_frac = src_x - x_floor as f32;
                let y_frac = src_y - y_floor as f32;

                let c00 = self.get_pixel(x_floor, y_floor);
                let c10 = self.get_pixel(x_ceil, y_floor);
                let c01 = self.get_pixel(x_floor, y_ceil);
                let c11 = self.get_pixel(x_ceil, y_ceil);

                let color = bilinear_interpolate(c00, c10, c01, c11, x_frac, y_frac);
                result.set_pixel(x, y, color);
            }
        }

        result
    }

    /// 水平反転
    pub fn flip_horizontal(&self) -> Image {
        let mut result = Image::new(self.width, self.height);

        for y in 0..self.height {
            for x in 0..self.width {
                let color = self.get_pixel(x, y);
                result.set_pixel(self.width - 1 - x, y, color);
            }
        }

        result
    }

    /// 垂直反転
    pub fn flip_vertical(&self) -> Image {
        let mut result = Image::new(self.width, self.height);

        for y in 0..self.height {
            for x in 0..self.width {
                let color = self.get_pixel(x, y);
                result.set_pixel(x, self.height - 1 - y, color);
            }
        }

        result
    }

    /// 90度時計回りに回転
    pub fn rotate_90_cw(&self) -> Image {
        let mut result = Image::new(self.height, self.width);

        for y in 0..self.height {
            for x in 0..self.width {
                let color = self.get_pixel(x, y);
                result.set_pixel(self.height - 1 - y, x, color);
            }
        }

        result
    }

    /// グレースケールに変換
    pub fn to_grayscale(&self) -> Image {
        let mut result = Image::new(self.width, self.height);

        for y in 0..self.height {
            for x in 0..self.width {
                let color = self.get_pixel(x, y);
                let gray = (color.red as u32 * 299 + color.green as u32 * 587 + color.blue as u32 * 114) / 1000;
                result.set_pixel(x, y, Color::with_alpha(gray as u8, gray as u8, gray as u8, color.alpha));
            }
        }

        result
    }
}

// ============================================================================
// BMP Decoder
// ============================================================================

/// BMPファイルヘッダ
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct BmpFileHeader {
    magic: [u8; 2],
    file_size: u32,
    reserved: u32,
    data_offset: u32,
}

/// BMP情報ヘッダ（BITMAPINFOHEADER）
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct BmpInfoHeader {
    header_size: u32,
    width: i32,
    height: i32,
    planes: u16,
    bpp: u16,
    compression: u32,
    image_size: u32,
    x_pixels_per_meter: i32,
    y_pixels_per_meter: i32,
    colors_used: u32,
    colors_important: u32,
}

/// BMP圧縮タイプ
const BI_RGB: u32 = 0;
const BI_RLE8: u32 = 1;
const BI_RLE4: u32 = 2;
const BI_BITFIELDS: u32 = 3;

/// 画像読み込みエラー
#[derive(Clone, Debug)]
pub enum ImageError {
    InvalidFormat,
    UnsupportedFormat,
    InvalidData,
    DecompressionError,
}

pub type ImageResult<T> = Result<T, ImageError>;

/// BMPファイルをデコード
pub fn decode_bmp(data: &[u8]) -> ImageResult<Image> {
    if data.len() < 54 {
        return Err(ImageError::InvalidFormat);
    }

    // マジックナンバーをチェック
    if data[0] != b'B' || data[1] != b'M' {
        return Err(ImageError::InvalidFormat);
    }

    // ヘッダを読み取り
    let file_header = unsafe {
        *(data.as_ptr() as *const BmpFileHeader)
    };

    let info_header = unsafe {
        *(data.as_ptr().add(14) as *const BmpInfoHeader)
    };

    let width = info_header.width.abs() as u32;
    let height = info_header.height.abs() as u32;
    let bpp = info_header.bpp;
    let compression = info_header.compression;
    let data_offset = file_header.data_offset as usize;
    let top_down = info_header.height < 0;

    // サポートされているフォーマットをチェック
    if compression != BI_RGB && compression != BI_BITFIELDS {
        return Err(ImageError::UnsupportedFormat);
    }

    if bpp != 24 && bpp != 32 && bpp != 8 {
        return Err(ImageError::UnsupportedFormat);
    }

    let mut image = Image::new(width, height);
    let pixel_data = &data[data_offset..];

    // 行のパディングを計算
    let row_size = ((bpp as u32 * width + 31) / 32 * 4) as usize;

    match bpp {
        24 => {
            // 24ビットBMP (BGR)
            for y in 0..height {
                let src_y = if top_down { y } else { height - 1 - y };
                let row_start = src_y as usize * row_size;

                for x in 0..width {
                    let idx = row_start + x as usize * 3;
                    if idx + 2 < pixel_data.len() {
                        let color = Color::new(
                            pixel_data[idx + 2],
                            pixel_data[idx + 1],
                            pixel_data[idx],
                        );
                        image.set_pixel(x, y, color);
                    }
                }
            }
        }
        32 => {
            // 32ビットBMP (BGRA)
            for y in 0..height {
                let src_y = if top_down { y } else { height - 1 - y };
                let row_start = src_y as usize * row_size;

                for x in 0..width {
                    let idx = row_start + x as usize * 4;
                    if idx + 3 < pixel_data.len() {
                        let color = Color::with_alpha(
                            pixel_data[idx + 2],
                            pixel_data[idx + 1],
                            pixel_data[idx],
                            pixel_data[idx + 3],
                        );
                        image.set_pixel(x, y, color);
                    }
                }
            }
        }
        8 => {
            // 8ビットパレットBMP
            let palette_offset = 14 + info_header.header_size as usize;
            let palette_size = if info_header.colors_used > 0 {
                info_header.colors_used as usize
            } else {
                256
            };

            // パレットを読み取り
            let mut palette = Vec::with_capacity(palette_size);
            for i in 0..palette_size {
                let idx = palette_offset + i * 4;
                if idx + 3 < data.len() {
                    palette.push(Color::new(data[idx + 2], data[idx + 1], data[idx]));
                } else {
                    palette.push(Color::BLACK);
                }
            }

            // ピクセルをデコード
            for y in 0..height {
                let src_y = if top_down { y } else { height - 1 - y };
                let row_start = src_y as usize * row_size;

                for x in 0..width {
                    let idx = row_start + x as usize;
                    if idx < pixel_data.len() {
                        let palette_idx = pixel_data[idx] as usize;
                        if palette_idx < palette.len() {
                            image.set_pixel(x, y, palette[palette_idx]);
                        }
                    }
                }
            }
        }
        _ => return Err(ImageError::UnsupportedFormat),
    }

    Ok(image)
}

// ============================================================================
// TGA Decoder (Simple)
// ============================================================================

/// TGAファイルをデコード（簡易実装）
pub fn decode_tga(data: &[u8]) -> ImageResult<Image> {
    if data.len() < 18 {
        return Err(ImageError::InvalidFormat);
    }

    let id_length = data[0] as usize;
    let color_map_type = data[1];
    let image_type = data[2];
    let width = u16::from_le_bytes([data[12], data[13]]) as u32;
    let height = u16::from_le_bytes([data[14], data[15]]) as u32;
    let bpp = data[16];
    let descriptor = data[17];

    // サポートされているタイプをチェック
    if image_type != 2 && image_type != 10 {
        // 非圧縮/RLE圧縮トゥルーカラー
        return Err(ImageError::UnsupportedFormat);
    }

    if bpp != 24 && bpp != 32 {
        return Err(ImageError::UnsupportedFormat);
    }

    let top_down = (descriptor & 0x20) != 0;
    let pixel_data_offset = 18 + id_length + if color_map_type != 0 { 
        // カラーマップをスキップ
        let cm_length = u16::from_le_bytes([data[5], data[6]]) as usize;
        let cm_entry_size = data[7] as usize;
        cm_length * ((cm_entry_size + 7) / 8)
    } else { 
        0 
    };

    let mut image = Image::new(width, height);
    let bytes_per_pixel = bpp as usize / 8;

    if image_type == 2 {
        // 非圧縮
        let pixel_data = &data[pixel_data_offset..];

        for y in 0..height {
            let dst_y = if top_down { y } else { height - 1 - y };

            for x in 0..width {
                let idx = (y * width + x) as usize * bytes_per_pixel;
                if idx + bytes_per_pixel <= pixel_data.len() {
                    let color = if bpp == 24 {
                        Color::new(pixel_data[idx + 2], pixel_data[idx + 1], pixel_data[idx])
                    } else {
                        Color::with_alpha(
                            pixel_data[idx + 2],
                            pixel_data[idx + 1],
                            pixel_data[idx],
                            pixel_data[idx + 3],
                        )
                    };
                    image.set_pixel(x, dst_y, color);
                }
            }
        }
    } else {
        // RLE圧縮
        let pixel_data = &data[pixel_data_offset..];
        let mut src_idx = 0;
        let mut x = 0u32;
        let mut y = 0u32;

        while y < height && src_idx < pixel_data.len() {
            let packet = pixel_data[src_idx];
            src_idx += 1;

            let count = (packet & 0x7F) as u32 + 1;
            let is_rle = (packet & 0x80) != 0;

            if is_rle {
                // RLEパケット
                if src_idx + bytes_per_pixel > pixel_data.len() {
                    break;
                }

                let color = if bpp == 24 {
                    Color::new(
                        pixel_data[src_idx + 2],
                        pixel_data[src_idx + 1],
                        pixel_data[src_idx],
                    )
                } else {
                    Color::with_alpha(
                        pixel_data[src_idx + 2],
                        pixel_data[src_idx + 1],
                        pixel_data[src_idx],
                        pixel_data[src_idx + 3],
                    )
                };
                src_idx += bytes_per_pixel;

                for _ in 0..count {
                    let dst_y = if top_down { y } else { height - 1 - y };
                    image.set_pixel(x, dst_y, color);
                    x += 1;
                    if x >= width {
                        x = 0;
                        y += 1;
                    }
                }
            } else {
                // Rawパケット
                for _ in 0..count {
                    if src_idx + bytes_per_pixel > pixel_data.len() {
                        break;
                    }

                    let color = if bpp == 24 {
                        Color::new(
                            pixel_data[src_idx + 2],
                            pixel_data[src_idx + 1],
                            pixel_data[src_idx],
                        )
                    } else {
                        Color::with_alpha(
                            pixel_data[src_idx + 2],
                            pixel_data[src_idx + 1],
                            pixel_data[src_idx],
                            pixel_data[src_idx + 3],
                        )
                    };
                    src_idx += bytes_per_pixel;

                    let dst_y = if top_down { y } else { height - 1 - y };
                    image.set_pixel(x, dst_y, color);
                    x += 1;
                    if x >= width {
                        x = 0;
                        y += 1;
                    }
                }
            }
        }
    }

    Ok(image)
}

// ============================================================================
// ICO/CUR Decoder
// ============================================================================

/// ICOファイルヘッダ
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IcoHeader {
    reserved: u16,
    image_type: u16, // 1=ICO, 2=CUR
    image_count: u16,
}

/// ICOディレクトリエントリ
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IcoDirEntry {
    width: u8,
    height: u8,
    color_count: u8,
    reserved: u8,
    color_planes: u16,
    bits_per_pixel: u16,
    image_size: u32,
    image_offset: u32,
}

/// ICOファイルをデコード
pub fn decode_ico(data: &[u8]) -> ImageResult<Vec<Image>> {
    if data.len() < 6 {
        return Err(ImageError::InvalidFormat);
    }

    let header = unsafe { *(data.as_ptr() as *const IcoHeader) };

    if header.reserved != 0 || (header.image_type != 1 && header.image_type != 2) {
        return Err(ImageError::InvalidFormat);
    }

    let image_count = header.image_count as usize;
    let mut images = Vec::with_capacity(image_count);

    for i in 0..image_count {
        let entry_offset = 6 + i * 16;
        if entry_offset + 16 > data.len() {
            break;
        }

        let entry = unsafe {
            *(data.as_ptr().add(entry_offset) as *const IcoDirEntry)
        };

        let image_offset = entry.image_offset as usize;
        let image_size = entry.image_size as usize;

        if image_offset + image_size > data.len() {
            continue;
        }

        let image_data = &data[image_offset..image_offset + image_size];

        // PNGまたはBMPをチェック
        if image_data.len() >= 8 && &image_data[0..8] == b"\x89PNG\r\n\x1a\n" {
            // PNG形式（簡易対応は省略）
            continue;
        } else {
            // BMP形式（DIBヘッダから）
            if let Ok(image) = decode_ico_bmp(image_data, entry.width, entry.height) {
                images.push(image);
            }
        }
    }

    if images.is_empty() {
        Err(ImageError::InvalidData)
    } else {
        Ok(images)
    }
}

/// ICO内のBMPをデコード
fn decode_ico_bmp(data: &[u8], width_hint: u8, height_hint: u8) -> ImageResult<Image> {
    if data.len() < 40 {
        return Err(ImageError::InvalidFormat);
    }

    let header = unsafe { *(data.as_ptr() as *const BmpInfoHeader) };

    let width = if width_hint == 0 { 256 } else { width_hint as u32 };
    let height = if height_hint == 0 { 256 } else { height_hint as u32 };
    let bpp = header.bpp;

    let mut image = Image::new(width, height);

    let pixel_data_offset = header.header_size as usize;
    let pixel_data = &data[pixel_data_offset..];

    match bpp {
        32 => {
            // 32ビット BGRA
            let row_size = width as usize * 4;

            for y in 0..height {
                let src_y = height - 1 - y; // ボトムアップ
                let row_start = src_y as usize * row_size;

                for x in 0..width {
                    let idx = row_start + x as usize * 4;
                    if idx + 3 < pixel_data.len() {
                        let color = Color::with_alpha(
                            pixel_data[idx + 2],
                            pixel_data[idx + 1],
                            pixel_data[idx],
                            pixel_data[idx + 3],
                        );
                        image.set_pixel(x, y, color);
                    }
                }
            }
        }
        24 => {
            // 24ビット BGR + マスク
            let row_size = ((24 * width + 31) / 32 * 4) as usize;
            let mask_row_size = ((width + 31) / 32 * 4) as usize;
            let mask_offset = height as usize * row_size;

            for y in 0..height {
                let src_y = height - 1 - y;
                let row_start = src_y as usize * row_size;
                let mask_row_start = mask_offset + src_y as usize * mask_row_size;

                for x in 0..width {
                    let idx = row_start + x as usize * 3;
                    let mask_byte_idx = mask_row_start + x as usize / 8;
                    let mask_bit = 7 - (x % 8);

                    if idx + 2 < pixel_data.len() {
                        let alpha = if mask_byte_idx < pixel_data.len() {
                            if (pixel_data[mask_byte_idx] >> mask_bit) & 1 != 0 {
                                0
                            } else {
                                255
                            }
                        } else {
                            255
                        };

                        let color = Color::with_alpha(
                            pixel_data[idx + 2],
                            pixel_data[idx + 1],
                            pixel_data[idx],
                            alpha,
                        );
                        image.set_pixel(x, y, color);
                    }
                }
            }
        }
        _ => return Err(ImageError::UnsupportedFormat),
    }

    Ok(image)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// アルファブレンディング
pub fn alpha_blend(bg: Color, fg: Color) -> Color {
    if fg.alpha == 255 {
        return fg;
    }
    if fg.alpha == 0 {
        return bg;
    }

    let alpha = fg.alpha as u32;
    let inv_alpha = 255 - alpha;

    Color::with_alpha(
        ((fg.red as u32 * alpha + bg.red as u32 * inv_alpha) / 255) as u8,
        ((fg.green as u32 * alpha + bg.green as u32 * inv_alpha) / 255) as u8,
        ((fg.blue as u32 * alpha + bg.blue as u32 * inv_alpha) / 255) as u8,
        255,
    )
}

/// バイリニア補間
fn bilinear_interpolate(c00: Color, c10: Color, c01: Color, c11: Color, x: f32, y: f32) -> Color {
    let inv_x = 1.0 - x;
    let inv_y = 1.0 - y;

    let r = (c00.red as f32 * inv_x * inv_y
        + c10.red as f32 * x * inv_y
        + c01.red as f32 * inv_x * y
        + c11.red as f32 * x * y) as u8;

    let g = (c00.green as f32 * inv_x * inv_y
        + c10.green as f32 * x * inv_y
        + c01.green as f32 * inv_x * y
        + c11.green as f32 * x * y) as u8;

    let b = (c00.blue as f32 * inv_x * inv_y
        + c10.blue as f32 * x * inv_y
        + c01.blue as f32 * inv_x * y
        + c11.blue as f32 * x * y) as u8;

    let a = (c00.alpha as f32 * inv_x * inv_y
        + c10.alpha as f32 * x * inv_y
        + c01.alpha as f32 * inv_x * y
        + c11.alpha as f32 * x * y) as u8;

    Color::with_alpha(r, g, b, a)
}

// ============================================================================
// Simple Icon Generator
// ============================================================================

/// アイコンを生成（シンプルな図形）
pub struct IconGenerator;

impl IconGenerator {
    /// 円形アイコンを生成
    pub fn circle(size: u32, color: Color) -> Image {
        let mut image = Image::new(size, size);
        let center = size as i32 / 2;
        let radius = center - 1;

        for y in 0..size as i32 {
            for x in 0..size as i32 {
                let dx = x - center;
                let dy = y - center;
                let dist_sq = dx * dx + dy * dy;

                if dist_sq <= radius * radius {
                    // アンチエイリアス（sqrtを使わない近似）
                    // ニュートン法で平方根を計算
                    let dist = fast_sqrt(dist_sq as f32);
                    let edge_dist = (dist - radius as f32).abs();
                    let alpha = if edge_dist < 1.0 {
                        ((1.0 - edge_dist) * color.alpha as f32) as u8
                    } else {
                        color.alpha
                    };
                    image.set_pixel(x as u32, y as u32, Color::with_alpha(color.red, color.green, color.blue, alpha));
                }
            }
        }

        image
    }

    /// 四角形アイコンを生成
    pub fn square(size: u32, color: Color, corner_radius: u32) -> Image {
        let mut image = Image::new(size, size);
        let r = corner_radius.min(size / 2);

        for y in 0..size {
            for x in 0..size {
                let in_corner = |cx: u32, cy: u32| -> bool {
                    let dx = if x < cx { cx - x } else { x - cx };
                    let dy = if y < cy { cy - y } else { y - cy };
                    dx * dx + dy * dy <= r * r
                };

                let inside = if x < r && y < r {
                    in_corner(r, r)
                } else if x >= size - r && y < r {
                    in_corner(size - r - 1, r)
                } else if x < r && y >= size - r {
                    in_corner(r, size - r - 1)
                } else if x >= size - r && y >= size - r {
                    in_corner(size - r - 1, size - r - 1)
                } else {
                    true
                };

                if inside {
                    image.set_pixel(x, y, color);
                }
            }
        }

        image
    }

    /// 三角形アイコンを生成（上向き）
    pub fn triangle(size: u32, color: Color) -> Image {
        let mut image = Image::new(size, size);
        let center = size as f32 / 2.0;

        for y in 0..size {
            let progress = y as f32 / size as f32;
            let half_width = progress * center;

            let start_x = (center - half_width) as u32;
            let end_x = (center + half_width) as u32;

            for x in start_x..=end_x.min(size - 1) {
                image.set_pixel(x, y, color);
            }
        }

        image
    }

    /// フォルダアイコンを生成
    pub fn folder(size: u32, color: Color) -> Image {
        let mut image = Image::new(size, size);

        // メインの四角形
        let main_rect = Rect::new(0, (size / 4) as i32, size, size * 3 / 4);
        image.fill_rect(main_rect, color);

        // タブ部分
        let tab_width = size / 3;
        let tab_rect = Rect::new(0, (size / 6) as i32, tab_width, size / 6);
        image.fill_rect(tab_rect, color);

        image
    }

    /// ファイルアイコンを生成
    pub fn file(size: u32, color: Color) -> Image {
        let mut image = Image::new(size, size);
        let corner_size = size / 4;

        // メインの四角形
        for y in 0..size {
            for x in 0..size {
                // 右上の角を除外
                if x >= size - corner_size && y < corner_size {
                    let local_x = x - (size - corner_size);
                    let local_y = y;
                    if local_x + local_y < corner_size {
                        continue;
                    }
                }
                image.set_pixel(x, y, color);
            }
        }

        // 折り返し部分（少し暗い色）
        let dark_color = Color::with_alpha(
            (color.red as u32 * 3 / 4) as u8,
            (color.green as u32 * 3 / 4) as u8,
            (color.blue as u32 * 3 / 4) as u8,
            color.alpha,
        );

        for y in 0..corner_size {
            for x in (size - corner_size)..size {
                let local_x = x - (size - corner_size);
                let local_y = y;
                if local_x <= local_y {
                    image.set_pixel(x, y, dark_color);
                }
            }
        }

        image
    }
}
