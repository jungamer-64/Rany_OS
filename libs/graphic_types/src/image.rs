// ============================================================================
// graphic_types/src/image.rs - Image Processing and Loading
// ============================================================================
//!
//! # 画像処理
//!
//! `BMP`、`PNG`（簡易）、アイコン等の画像フォーマット対応。
//!
//! ## 機能
//! - BMPファイル読み込み
//! - PNG簡易デコード
//! - 画像リサイズ・変換
//! - アルファブレンディング
//!
//! Note: Framebuffer drawing logic is excluded to keep this crate kernel-independent.

// Allow common casting operations in image processing code
#![allow(dead_code)]
#![allow(clippy::cast_lossless)] // u8->u32, u16->u32 are safe and common
#![allow(clippy::cast_precision_loss)] // u32->f32 for interpolation
#![allow(clippy::cast_possible_wrap)] // u32->i32 for coordinate math
#![allow(clippy::cast_sign_loss)] // i32->u32 after bounds checking
#![allow(clippy::cast_possible_truncation)] // f32->u8 for color values
#![allow(clippy::must_use_candidate)] // Image builder methods return Self
#![allow(clippy::return_self_not_must_use)] // Builder pattern methods
#![allow(clippy::doc_markdown)] // Many format names like DIBHeader
#![allow(clippy::ptr_as_ptr)] // Pointer casts in image processing
#![allow(clippy::branches_sharing_code)] // Kept for readability
#![allow(clippy::manual_div_ceil)] // Ceiling division pattern
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)] // Some functions use Vec

use alloc::vec;
use alloc::vec::Vec;

use crate::{Color, PixelFormat, Rect};

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
    i = 0x5f37_59df - (i >> 1);
    let mut y = f32::from_bits(i);

    // ニュートン法で精度を上げる
    y = y * (1.5 - 0.5 * x * y * y);
    y = y * (1.5 - 0.5 * x * y * y);

    1.0 / y
}

// ============================================================================
// Image Types
// ============================================================================

/// Immutable view into pixel data (slice-backed, no allocation)
///
/// Enables zero-copy access to image data stored in arbitrary memory
/// regions such as VRAM, DMA buffers, or Exchange Heap.
#[repr(C)]
pub struct ImageView<'a> {
    data: &'a [u8],
    width: u32,
    height: u32,
    /// Bytes per row (may be larger than width * bytes_per_pixel for alignment)
    stride: u32,
    format: PixelFormat,
}

impl<'a> ImageView<'a> {
    /// Create a new immutable image view
    ///
    /// # Safety
    /// The caller must ensure `data` has at least `stride * height` bytes.
    #[must_use]
    pub fn new(
        data: &'a [u8],
        width: u32,
        height: u32,
        stride: u32,
        format: PixelFormat,
    ) -> Option<Self> {
        let required = (stride as usize).checked_mul(height as usize)?;
        if data.len() < required {
            return None;
        }
        Some(Self {
            data,
            width,
            height,
            stride,
            format,
        })
    }

    /// Get the width in pixels
    #[inline]
    #[must_use]
    pub const fn width(&self) -> u32 {
        self.width
    }

    /// Get the height in pixels
    #[inline]
    #[must_use]
    pub const fn height(&self) -> u32 {
        self.height
    }

    /// Get the stride (bytes per row)
    #[inline]
    #[must_use]
    pub const fn stride(&self) -> u32 {
        self.stride
    }

    /// Get the pixel format
    #[inline]
    #[must_use]
    pub const fn format(&self) -> PixelFormat {
        self.format
    }

    /// Get the raw pixel data slice
    #[inline]
    #[must_use]
    pub const fn data(&self) -> &[u8] {
        self.data
    }

    /// Get a pixel at (x, y)
    #[must_use]
    pub fn get_pixel(&self, x: u32, y: u32) -> Color {
        if x >= self.width || y >= self.height {
            return Color::TRANSPARENT;
        }
        let bpp = self.format.bytes_per_pixel();
        let offset = (y as usize) * (self.stride as usize) + (x as usize) * bpp;
        if offset + bpp > self.data.len() {
            return Color::TRANSPARENT;
        }
        self.format.decode_color_bytes(&self.data[offset..])
    }
}

/// Mutable view into pixel data (for VRAM/DMA buffer access)
///
/// Enables zero-copy manipulation of image data in arbitrary memory
/// regions, eliminating the need for intermediate copies.
#[repr(C)]
pub struct ImageViewMut<'a> {
    data: &'a mut [u8],
    width: u32,
    height: u32,
    stride: u32,
    format: PixelFormat,
}

impl<'a> ImageViewMut<'a> {
    /// Create a new mutable image view
    ///
    /// # Safety
    /// The caller must ensure `data` has at least `stride * height` bytes.
    #[must_use]
    pub fn new(
        data: &'a mut [u8],
        width: u32,
        height: u32,
        stride: u32,
        format: PixelFormat,
    ) -> Option<Self> {
        let required = (stride as usize).checked_mul(height as usize)?;
        if data.len() < required {
            return None;
        }
        Some(Self {
            data,
            width,
            height,
            stride,
            format,
        })
    }

    /// Get the width in pixels
    #[inline]
    #[must_use]
    pub const fn width(&self) -> u32 {
        self.width
    }

    /// Get the height in pixels
    #[inline]
    #[must_use]
    pub const fn height(&self) -> u32 {
        self.height
    }

    /// Get the stride (bytes per row)
    #[inline]
    #[must_use]
    pub const fn stride(&self) -> u32 {
        self.stride
    }

    /// Get the pixel format
    #[inline]
    #[must_use]
    pub const fn format(&self) -> PixelFormat {
        self.format
    }

    /// Get the raw pixel data slice (immutable)
    #[inline]
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.data
    }

    /// Get the raw pixel data slice (mutable)
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        self.data
    }

    /// Get a pixel at (x, y)
    #[must_use]
    pub fn get_pixel(&self, x: u32, y: u32) -> Color {
        if x >= self.width || y >= self.height {
            return Color::TRANSPARENT;
        }
        let bpp = self.format.bytes_per_pixel();
        let offset = (y as usize) * (self.stride as usize) + (x as usize) * bpp;
        if offset + bpp > self.data.len() {
            return Color::TRANSPARENT;
        }
        self.format.decode_color_bytes(&self.data[offset..])
    }

    /// Set a pixel at (x, y)
    pub fn set_pixel(&mut self, x: u32, y: u32, color: Color) {
        if x >= self.width || y >= self.height {
            return;
        }
        let bpp = self.format.bytes_per_pixel();
        let offset = (y as usize) * (self.stride as usize) + (x as usize) * bpp;
        self.format
            .encode_color_bytes(color, &mut self.data[offset..]);
    }

    /// Fill a rectangle with a solid color
    pub fn fill_rect(&mut self, rect: Rect, color: Color) {
        let x_start = rect.x.max(0) as u32;
        let y_start = rect.y.max(0) as u32;
        let x_end = (rect.x + rect.width as i32).min(self.width as i32) as u32;
        let y_end = (rect.y + rect.height as i32).min(self.height as i32) as u32;

        for y in y_start..y_end {
            for x in x_start..x_end {
                self.set_pixel(x, y, color);
            }
        }
    }
}

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

/// Determine the corner-center coordinate for one axis of a rounded rect.
///
/// Returns `Some(center)` if `coord` falls inside the corner radius, `None` otherwise.
fn corner_center(coord: u32, size: u32, r: u32) -> Option<u32> {
    if coord < r {
        Some(r)
    } else if coord >= size - r {
        Some(size - r - 1)
    } else {
        None
    }
}

/// Test whether pixel (x, y) is inside a rounded rectangle of the given `size` and radius `r`.
fn is_inside_rounded_rect(x: u32, y: u32, size: u32, r: u32) -> bool {
    if r == 0 {
        return true;
    }
    match (corner_center(x, size, r), corner_center(y, size, r)) {
        (Some(cx), Some(cy)) => {
            let dx = cx.abs_diff(x);
            let dy = cy.abs_diff(y);
            dx * dx + dy * dy <= r * r
        }
        _ => true,
    }
}

impl Image {
    /// Try to create an empty image with checked arithmetic
    ///
    /// Returns `Err(ImageError::DimensionsTooLarge)` if:
    /// - The dimensions would cause integer overflow
    /// - The total size exceeds `MAX_IMAGE_SIZE`
    pub fn try_new(width: u32, height: u32) -> ImageResult<Self> {
        let size = (width as usize)
            .checked_mul(height as usize)
            .and_then(|s| s.checked_mul(4))
            .ok_or(ImageError::DimensionsTooLarge)?;

        if size > MAX_IMAGE_SIZE {
            return Err(ImageError::DimensionsTooLarge);
        }

        Ok(Self {
            data: vec![0u8; size],
            width,
            height,
        })
    }

    /// Create an empty image (panics on overflow, prefer `try_new`)
    #[must_use]
    pub fn new(width: u32, height: u32) -> Self {
        Self::try_new(width, height).expect("Image dimensions too large")
    }

    /// Try to create a solid-color filled image with checked arithmetic
    pub fn try_filled(width: u32, height: u32, color: Color) -> ImageResult<Self> {
        let pixel_count = (width as usize)
            .checked_mul(height as usize)
            .ok_or(ImageError::DimensionsTooLarge)?;
        let byte_size = pixel_count
            .checked_mul(4)
            .ok_or(ImageError::DimensionsTooLarge)?;

        if byte_size > MAX_IMAGE_SIZE {
            return Err(ImageError::DimensionsTooLarge);
        }

        let mut data = Vec::with_capacity(byte_size);
        for _ in 0..pixel_count {
            data.push(color.red);
            data.push(color.green);
            data.push(color.blue);
            data.push(color.alpha);
        }

        Ok(Self {
            data,
            width,
            height,
        })
    }

    /// Create a solid-color filled image (panics on overflow, prefer `try_filled`)
    #[must_use]
    pub fn filled(width: u32, height: u32, color: Color) -> Self {
        Self::try_filled(width, height, color).expect("Image dimensions too large")
    }

    /// 幅を取得
    #[must_use]
    pub const fn width(&self) -> u32 {
        self.width
    }

    /// 高さを取得
    #[must_use]
    pub const fn height(&self) -> u32 {
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

    /// Get an immutable view of this image
    ///
    /// The returned view uses RGBA8888 format with no padding (stride = width * 4).
    pub fn as_view(&self) -> ImageView<'_> {
        ImageView {
            data: &self.data,
            width: self.width,
            height: self.height,
            stride: self.width * 4,
            format: PixelFormat::Rgba8888,
        }
    }

    /// Get a mutable view of this image
    ///
    /// The returned view uses RGBA8888 format with no padding (stride = width * 4).
    pub fn as_view_mut(&mut self) -> ImageViewMut<'_> {
        ImageViewMut {
            data: &mut self.data,
            width: self.width,
            height: self.height,
            stride: self.width * 4,
            format: PixelFormat::Rgba8888,
        }
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
    #[allow(clippy::cast_sign_loss)]
    pub fn fill_rect(&mut self, rect: Rect, color: Color) {
        for y in rect.y.max(0)..(rect.y + rect.height as i32).min(self.height as i32) {
            for x in rect.x.max(0)..(rect.x + rect.width as i32).min(self.width as i32) {
                self.set_pixel(x as u32, y as u32, color);
            }
        }
    }

    /// 別の画像を描画
    #[allow(clippy::cast_sign_loss)]
    #[allow(clippy::similar_names)]
    pub fn blit(&mut self, src: &Self, dst_x: i32, dst_y: i32) {
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

    // draw_to_framebuffer removed (moved to kernel Framebuffer::draw_image)

    /// リサイズ（最近傍補間）
    #[allow(clippy::similar_names)]
    pub fn resize_nearest(&self, new_width: u32, new_height: u32) -> Self {
        let mut result = Self::new(new_width, new_height);

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
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    #[allow(clippy::similar_names)]
    pub fn resize_bilinear(&self, new_width: u32, new_height: u32) -> Self {
        let mut result = Self::new(new_width, new_height);

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
    pub fn flip_horizontal(&self) -> Self {
        let mut result = Self::new(self.width, self.height);

        for y in 0..self.height {
            for x in 0..self.width {
                let color = self.get_pixel(x, y);
                result.set_pixel(self.width - 1 - x, y, color);
            }
        }

        result
    }

    /// 垂直反転
    pub fn flip_vertical(&self) -> Self {
        let mut result = Self::new(self.width, self.height);

        for y in 0..self.height {
            for x in 0..self.width {
                let color = self.get_pixel(x, y);
                result.set_pixel(x, self.height - 1 - y, color);
            }
        }

        result
    }

    /// 90度時計回りに回転
    pub fn rotate_90_cw(&self) -> Self {
        let mut result = Self::new(self.height, self.width);

        for y in 0..self.height {
            for x in 0..self.width {
                let color = self.get_pixel(x, y);
                result.set_pixel(self.height - 1 - y, x, color);
            }
        }

        result
    }

    /// グレースケールに変換
    #[allow(clippy::cast_possible_truncation)]
    pub fn to_grayscale(&self) -> Self {
        let mut result = Self::new(self.width, self.height);

        for y in 0..self.height {
            for x in 0..self.width {
                let color = self.get_pixel(x, y);
                let gray =
                    (color.red as u32 * 299 + color.green as u32 * 587 + color.blue as u32 * 114)
                        / 1_000;
                result.set_pixel(
                    x,
                    y,
                    Color::with_alpha(gray as u8, gray as u8, gray as u8, color.alpha),
                );
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
    /// Image dimensions would cause integer overflow or exceed maximum size
    DimensionsTooLarge,
}

pub type ImageResult<T> = Result<T, ImageError>;

/// Maximum allowed image size in bytes (256 MB) to prevent DoS attacks
pub const MAX_IMAGE_SIZE: usize = 256 * 1024 * 1024;

/// Helper to read a Copy struct from a byte slice at a given offset.
/// Centralizes the unsafe bytes->struct conversion.
fn read_struct_from_slice<T: Copy>(data: &[u8], offset: usize) -> Option<T> {
    use core::mem;
    let size = mem::size_of::<T>();
    let end = offset.checked_add(size)?;
    if end > data.len() {
        return None;
    }
    let ptr = unsafe { data.as_ptr().add(offset) as *const T };
    Some(unsafe { core::ptr::read_unaligned(ptr) })
}

/// BMPファイルをデコード
///
/// # Errors
/// Returns error if format is invalid or unsupported.
#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::cast_sign_loss)]
pub fn decode_bmp(data: &[u8]) -> ImageResult<Image> {
    if data.len() < 54 {
        return Err(ImageError::InvalidFormat);
    }

    // マジックナンバーをチェック
    if data[0] != b'B' || data[1] != b'M' {
        return Err(ImageError::InvalidFormat);
    }

    // ヘッダを読み取り
    let file_header =
        read_struct_from_slice::<BmpFileHeader>(data, 0).ok_or(ImageError::InvalidFormat)?;

    let info_header =
        read_struct_from_slice::<BmpInfoHeader>(data, 14).ok_or(ImageError::InvalidFormat)?;

    let width = info_header.width.unsigned_abs();
    let height = info_header.height.unsigned_abs();
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

    let mut image = Image::try_new(width, height)?;
    let pixel_data = &data[data_offset..];
    let row_size = ((bpp as u32 * width).div_ceil(32) * 4) as usize;

    match bpp {
        24 => decode_bmp_rows_24(pixel_data, width, height, top_down, row_size, &mut image),
        32 => decode_bmp_rows_32(pixel_data, width, height, top_down, row_size, &mut image),
        8 => decode_bmp_rows_8(data, pixel_data, &info_header, width, height, top_down, row_size, &mut image),
        _ => return Err(ImageError::UnsupportedFormat),
    }

    Ok(image)
}

/// Decode 24-bit BGR rows into an Image.
fn decode_bmp_rows_24(pixel_data: &[u8], width: u32, height: u32, top_down: bool, row_size: usize, image: &mut Image) {
    for y in 0..height {
        let src_y = if top_down { y } else { height - 1 - y };
        let row_start = src_y as usize * row_size;
        for x in 0..width {
            let idx = row_start + x as usize * 3;
            if idx + 2 < pixel_data.len() {
                let color = Color::new(pixel_data[idx + 2], pixel_data[idx + 1], pixel_data[idx]);
                image.set_pixel(x, y, color);
            }
        }
    }
}

/// Decode 32-bit BGRA rows into an Image.
fn decode_bmp_rows_32(pixel_data: &[u8], width: u32, height: u32, top_down: bool, row_size: usize, image: &mut Image) {
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

/// Decode 8-bit palette-indexed rows into an Image.
fn decode_bmp_rows_8(
    data: &[u8],
    pixel_data: &[u8],
    info_header: &BmpInfoHeader,
    width: u32,
    height: u32,
    top_down: bool,
    row_size: usize,
    image: &mut Image,
) {
    let palette_offset = 14 + info_header.header_size as usize;
    let palette_size = if info_header.colors_used > 0 {
        info_header.colors_used as usize
    } else {
        256
    };

    let mut palette = Vec::with_capacity(palette_size);
    for i in 0..palette_size {
        let idx = palette_offset + i * 4;
        if idx + 3 < data.len() {
            palette.push(Color::new(data[idx + 2], data[idx + 1], data[idx]));
        } else {
            palette.push(Color::BLACK);
        }
    }

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

/// Decode BMP into a pre-allocated buffer (zero-allocation variant)
///
/// This function decodes a BMP image directly into the provided `ImageViewMut`,
/// avoiding any heap allocation. Useful for:
/// - Kernel bootstrap (before allocator is ready)
/// - VRAM/DMA buffer direct writes
/// - Exchange Heap integration
///
/// # Errors
/// Returns error if:
/// - BMP format is invalid
/// - Output buffer dimensions don't match the image
#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::cast_sign_loss)]
pub fn decode_bmp_into(data: &[u8], output: &mut ImageViewMut) -> ImageResult<()> {
    let (pixel_data, row_size, width, height, bpp, top_down) = validate_bmp_headers(data, output)?;

    match bpp {
        24 => decode_bmp_rows_24_into(pixel_data, output, row_size, width, height, top_down),
        32 => decode_bmp_rows_32_into(pixel_data, output, row_size, width, height, top_down),
        _ => return Err(ImageError::UnsupportedFormat),
    }

    Ok(())
}

/// BMP圧縮形式・ビット深度・サイズを検証
fn validate_bmp_format(
    compression: u32,
    bpp: u16,
    width: u32,
    height: u32,
    output: &ImageViewMut,
) -> ImageResult<()> {
    if output.width() != width || output.height() != height {
        return Err(ImageError::InvalidData);
    }
    if compression != BI_RGB && compression != BI_BITFIELDS {
        return Err(ImageError::UnsupportedFormat);
    }
    if bpp != 24 && bpp != 32 {
        return Err(ImageError::UnsupportedFormat);
    }
    Ok(())
}

/// Validate BMP file/info headers and return the pixel data slice with metadata.
#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::cast_sign_loss)]
fn validate_bmp_headers<'a>(
    data: &'a [u8],
    output: &ImageViewMut,
) -> ImageResult<(&'a [u8], usize, u32, u32, u16, bool)> {
    if data.len() < 54 {
        return Err(ImageError::InvalidFormat);
    }
    if data[0] != b'B' || data[1] != b'M' {
        return Err(ImageError::InvalidFormat);
    }

    let file_header =
        read_struct_from_slice::<BmpFileHeader>(data, 0).ok_or(ImageError::InvalidFormat)?;
    let info_header =
        read_struct_from_slice::<BmpInfoHeader>(data, 14).ok_or(ImageError::InvalidFormat)?;

    let width = info_header.width.unsigned_abs();
    let height = info_header.height.unsigned_abs();
    let bpp = info_header.bpp;
    let compression = info_header.compression;
    let data_offset = file_header.data_offset as usize;
    let top_down = info_header.height < 0;

    validate_bmp_format(compression, bpp, width, height, output)?;

    let pixel_data = &data[data_offset..];
    let row_size = ((bpp as u32 * width).div_ceil(32) * 4) as usize;
    Ok((pixel_data, row_size, width, height, bpp, top_down))
}

/// Decode 24-bpp BMP rows into the output view.
fn decode_bmp_rows_24_into(
    pixel_data: &[u8],
    output: &mut ImageViewMut,
    row_size: usize,
    width: u32,
    height: u32,
    top_down: bool,
) {
    for y in 0..height {
        let src_y = if top_down { y } else { height - 1 - y };
        let row_start = src_y as usize * row_size;
        for x in 0..width {
            let idx = row_start + x as usize * 3;
            if idx + 2 < pixel_data.len() {
                let color =
                    Color::new(pixel_data[idx + 2], pixel_data[idx + 1], pixel_data[idx]);
                output.set_pixel(x, y, color);
            }
        }
    }
}

/// Decode 32-bpp BMP rows into the output view.
fn decode_bmp_rows_32_into(
    pixel_data: &[u8],
    output: &mut ImageViewMut,
    row_size: usize,
    width: u32,
    height: u32,
    top_down: bool,
) {
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
                output.set_pixel(x, y, color);
            }
        }
    }
}

// ============================================================================
// TGA Decoder (Simple)
// ============================================================================

/// Read a single TGA pixel (BGR or BGRA) from the given offset.
///
/// Returns the decoded `Color` from the pixel data at `offset`.
#[inline]
fn read_tga_pixel(pixel_data: &[u8], offset: usize, bpp: u8) -> Color {
    if bpp == 24 {
        Color::new(
            pixel_data[offset + 2],
            pixel_data[offset + 1],
            pixel_data[offset],
        )
    } else {
        Color::with_alpha(
            pixel_data[offset + 2],
            pixel_data[offset + 1],
            pixel_data[offset],
            pixel_data[offset + 3],
        )
    }
}

/// Advance the TGA scan position by one pixel, wrapping to the next row.
#[inline]
fn tga_advance_pixel(x: &mut u32, y: &mut u32, width: u32) {
    *x += 1;
    if *x >= width {
        *x = 0;
        *y += 1;
    }
}

/// Compute the destination Y coordinate for a TGA scanline.
#[inline]
fn tga_dst_y(y: u32, height: u32, top_down: bool) -> u32 {
    if top_down { y } else { height - 1 - y }
}

/// Decode uncompressed (type 2) TGA pixel data into an image.
fn decode_tga_uncompressed(
    pixel_data: &[u8],
    image: &mut Image,
    width: u32,
    height: u32,
    bpp: u8,
    top_down: bool,
) {
    let bytes_per_pixel = bpp as usize / 8;

    for y in 0..height {
        let dst_y = tga_dst_y(y, height, top_down);

        for x in 0..width {
            let idx = (y * width + x) as usize * bytes_per_pixel;
            if idx + bytes_per_pixel <= pixel_data.len() {
                let color = read_tga_pixel(pixel_data, idx, bpp);
                image.set_pixel(x, dst_y, color);
            }
        }
    }
}

/// Decode RLE-compressed (type 10) TGA pixel data into an image.
fn decode_tga_rle(
    pixel_data: &[u8],
    image: &mut Image,
    width: u32,
    height: u32,
    bpp: u8,
    top_down: bool,
) {
    let bytes_per_pixel = bpp as usize / 8;
    let mut src_idx = 0;
    let mut x = 0u32;
    let mut y = 0u32;

    while y < height && src_idx < pixel_data.len() {
        let packet = pixel_data[src_idx];
        src_idx += 1;

        let count = (packet & 0x7F) as u32 + 1;
        let is_rle = (packet & 0x80) != 0;

        if is_rle {
            src_idx = decode_tga_rle_packet(
                pixel_data, image, src_idx, count, bytes_per_pixel, bpp,
                width, height, top_down, &mut x, &mut y,
            );
        } else {
            src_idx = decode_tga_raw_packet(
                pixel_data, image, src_idx, count, bytes_per_pixel, bpp,
                width, height, top_down, &mut x, &mut y,
            );
        }
    }
}

/// Decode a single RLE packet (repeated color) into the image.
///
/// Returns the updated `src_idx`.
fn decode_tga_rle_packet(
    pixel_data: &[u8],
    image: &mut Image,
    mut src_idx: usize,
    count: u32,
    bytes_per_pixel: usize,
    bpp: u8,
    width: u32,
    height: u32,
    top_down: bool,
    x: &mut u32,
    y: &mut u32,
) -> usize {
    if src_idx + bytes_per_pixel > pixel_data.len() {
        return pixel_data.len(); // signal break
    }

    let color = read_tga_pixel(pixel_data, src_idx, bpp);
    src_idx += bytes_per_pixel;

    for _ in 0..count {
        let dst_y = tga_dst_y(*y, height, top_down);
        image.set_pixel(*x, dst_y, color);
        tga_advance_pixel(x, y, width);
    }
    src_idx
}

/// Decode a single raw packet (sequence of distinct colors) into the image.
///
/// Returns the updated `src_idx`.
fn decode_tga_raw_packet(
    pixel_data: &[u8],
    image: &mut Image,
    mut src_idx: usize,
    count: u32,
    bytes_per_pixel: usize,
    bpp: u8,
    width: u32,
    height: u32,
    top_down: bool,
    x: &mut u32,
    y: &mut u32,
) -> usize {
    for _ in 0..count {
        if src_idx + bytes_per_pixel > pixel_data.len() {
            break;
        }

        let color = read_tga_pixel(pixel_data, src_idx, bpp);
        src_idx += bytes_per_pixel;

        let dst_y = tga_dst_y(*y, height, top_down);
        image.set_pixel(*x, dst_y, color);
        tga_advance_pixel(x, y, width);
    }
    src_idx
}

/// TGAファイルをデコード（簡易実装）
///
/// # Errors
/// Returns error if format is invalid or unsupported.
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
    let pixel_data_offset = 18
        + id_length
        + if color_map_type != 0 {
            // カラーマップをスキップ
            let cm_length = u16::from_le_bytes([data[5], data[6]]) as usize;
            let cm_entry_size = data[7] as usize;
            cm_length * cm_entry_size.div_ceil(8)
        } else {
            0
        };

    let mut image = Image::try_new(width, height)?;
    let pixel_data = &data[pixel_data_offset..];

    if image_type == 2 {
        decode_tga_uncompressed(pixel_data, &mut image, width, height, bpp, top_down);
    } else {
        decode_tga_rle(pixel_data, &mut image, width, height, bpp, top_down);
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

/// 単一のICOエントリをデコードを試みる (PNGはスキップ、BMPをデコード)
fn try_decode_ico_entry(data: &[u8], index: usize) -> Option<Image> {
    let entry_offset = 6 + index * 16;
    if entry_offset + 16 > data.len() {
        return None;
    }
    let entry = read_struct_from_slice::<IcoDirEntry>(data, entry_offset)?;
    let image_offset = entry.image_offset as usize;
    let image_size = entry.image_size as usize;
    if image_offset + image_size > data.len() {
        return None;
    }
    let image_data = &data[image_offset..image_offset + image_size];
    // PNG形式はスキップ
    if image_data.len() >= 8 && &image_data[0..8] == b"\x89PNG\r\n\x1a\n" {
        return None;
    }
    decode_ico_bmp(image_data, entry.width, entry.height).ok()
}

/// ICOヘッダを検証して画像数を返す
fn validate_ico_header(data: &[u8]) -> ImageResult<usize> {
    if data.len() < 6 {
        return Err(ImageError::InvalidFormat);
    }
    let header = read_struct_from_slice::<IcoHeader>(data, 0).ok_or(ImageError::InvalidFormat)?;
    if header.reserved != 0 || (header.image_type != 1 && header.image_type != 2) {
        return Err(ImageError::InvalidFormat);
    }
    Ok(header.image_count as usize)
}

/// ICOファイルをデコード
///
/// # Errors
/// Returns error if format is invalid or unsupported.
pub fn decode_ico(data: &[u8]) -> ImageResult<Vec<Image>> {
    let image_count = validate_ico_header(data)?;
    let mut images = Vec::with_capacity(image_count);

    for i in 0..image_count {
        if let Some(image) = try_decode_ico_entry(data, i) {
            images.push(image);
        }
    }

    if images.is_empty() {
        return Err(ImageError::InvalidData);
    }

    Ok(images)
}

/// ICO内のBMPをデコード
fn decode_ico_bmp(data: &[u8], width_hint: u8, height_hint: u8) -> ImageResult<Image> {
    if data.len() < 40 {
        return Err(ImageError::InvalidFormat);
    }

    let header =
        read_struct_from_slice::<BmpInfoHeader>(data, 0).ok_or(ImageError::InvalidFormat)?;

    let width = if width_hint == 0 {
        256
    } else {
        width_hint as u32
    };
    let height = if height_hint == 0 {
        256
    } else {
        height_hint as u32
    };
    let bpp = header.bpp;

    let mut image = Image::try_new(width, height)?;

    let pixel_data_offset = header.header_size as usize;
    let pixel_data = &data[pixel_data_offset..];

    match bpp {
        32 => decode_32bpp_ico_rows(&mut image, pixel_data, width, height),
        24 => decode_24bpp_ico_rows(&mut image, pixel_data, width, height),
        _ => return Err(ImageError::UnsupportedFormat),
    }

    Ok(image)
}

/// 32ビットBGRA行をデコード
fn decode_32bpp_ico_rows(image: &mut Image, pixel_data: &[u8], width: u32, height: u32) {
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

/// 24ビットBGR + マスク行をデコード
fn decode_24bpp_ico_rows(image: &mut Image, pixel_data: &[u8], width: u32, height: u32) {
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

// ============================================================================
// Helper Functions
// ============================================================================

/// アルファブレンディング
#[allow(clippy::cast_possible_truncation)]
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
#[allow(clippy::many_single_char_names)]
#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::cast_sign_loss)]
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
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
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
                    image.set_pixel(
                        x as u32,
                        y as u32,
                        Color::with_alpha(color.red, color.green, color.blue, alpha),
                    );
                }
            }
        }

        image
    }

    /// 四角形アイコンを生成
    ///
    /// Corner hit-test is delegated to [`is_inside_rounded_rect`].
    pub fn square(size: u32, color: Color, corner_radius: u32) -> Image {
        let mut image = Image::new(size, size);
        let r = corner_radius.min(size / 2);

        for y in 0..size {
            for x in 0..size {
                if is_inside_rounded_rect(x, y, size, r) {
                    image.set_pixel(x, y, color);
                }
            }
        }

        image
    }

    /// 三角形アイコンを生成（上向き）
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
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
    #[allow(clippy::cast_possible_wrap)]
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
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_possible_wrap)]
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

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::*;

    pub fn try_new_overflow_smoke() -> bool {
        let result = Image::try_new(u32::MAX, u32::MAX);
        matches!(result, Err(ImageError::DimensionsTooLarge))
    }

    pub fn try_new_max_size_smoke() -> bool {
        let result = Image::try_new(16384, 16384);
        matches!(result, Err(ImageError::DimensionsTooLarge))
    }

    pub fn try_new_valid_smoke() -> bool {
        match Image::try_new(100, 100) {
            Ok(img) => img.width() == 100 && img.height() == 100,
            Err(_) => false,
        }
    }

    pub fn try_filled_overflow_smoke() -> bool {
        let result = Image::try_filled(u32::MAX, 2, Color::RED);
        matches!(result, Err(ImageError::DimensionsTooLarge))
    }

    pub fn image_view_basic_smoke() -> bool {
        let mut img = Image::new(10, 10);
        img.set_pixel(5, 5, Color::RED);

        let view = img.as_view();
        if view.width() != 10 || view.height() != 10 || view.stride() != 40 {
            return false;
        }

        let pixel = view.get_pixel(5, 5);
        pixel.red == 255 && pixel.green == 0 && pixel.blue == 0
    }

    pub fn image_view_mut_set_pixel_smoke() -> bool {
        let mut img = Image::new(10, 10);

        {
            let mut view = img.as_view_mut();
            view.set_pixel(3, 3, Color::BLUE);
        }

        let pixel = img.get_pixel(3, 3);
        pixel.blue == 255 && pixel.red == 0
    }

    pub fn image_view_mut_fill_rect_smoke() -> bool {
        let mut img = Image::new(10, 10);

        {
            let mut view = img.as_view_mut();
            view.fill_rect(Rect::new(2, 2, 3, 3), Color::GREEN);
        }

        img.get_pixel(3, 3).green == 255 && img.get_pixel(0, 0).green == 0
    }

    pub fn image_view_out_of_bounds_smoke() -> bool {
        let img = Image::new(10, 10);
        let view = img.as_view();
        let pixel = view.get_pixel(100, 100);
        pixel.alpha == 0
    }

    pub fn image_view_external_buffer_smoke() -> bool {
        let mut buffer = vec![0u8; 100 * 4];
        let mut view = match ImageViewMut::new(&mut buffer, 10, 10, 40, PixelFormat::Rgba8888) {
            Some(v) => v,
            None => return false,
        };

        view.set_pixel(0, 0, Color::RED);

        buffer[0] == 255 && buffer[1] == 0 && buffer[2] == 0 && buffer[3] == 255
    }

    pub fn image_view_stride_smoke() -> bool {
        let mut buffer = vec![0u8; 48 * 10];
        let mut view = match ImageViewMut::new(&mut buffer, 10, 10, 48, PixelFormat::Rgba8888) {
            Some(v) => v,
            None => return false,
        };

        view.set_pixel(0, 1, Color::BLUE);

        buffer[48 + 2] == 255
    }

    pub fn max_image_size_constant_smoke() -> bool {
        MAX_IMAGE_SIZE == 256 * 1024 * 1024
    }
}
