//! Rendering owns its destination for the lifetime of every drawing operation.
//! RAM planes use ordinary slices; scanout planes retain exclusive mapped byte
//! access through HAL. Geometry is checked before either destination is published.
#![forbid(unsafe_code)]

use super::{BitmapFont, Color, PixelFormat, Point, Rect};
use alloc::vec::Vec;
use hal::{mmio, scanout::ScanoutBuffer};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FramebufferError {
    BufferTooSmall,
    OutOfMemory,
}

pub use graphic_types::FramebufferLayout;

/// Both storage forms transfer their write authority into the framebuffer.
/// RAM storage can also be used as an offscreen rendering target.
pub enum PixelBuffer {
    Memory(Vec<u8>),
    Scanout(ScanoutBuffer),
}
impl PixelBuffer {
    fn len(&self) -> usize {
        match self {
            Self::Memory(bytes) => bytes.len(),
            Self::Scanout(mapping) => mapping.len(),
        }
    }
    fn write(&mut self, offset: usize, data: &[u8]) {
        match self {
            Self::Memory(bytes) => bytes[offset..offset + data.len()].copy_from_slice(data),
            Self::Scanout(mapping) => {
                let mut span = mapping
                    .region_mut(offset, data.len())
                    .expect("validated drawing span");
                span.write_bytes(data).expect("exact drawing byte count");
            }
        }
    }
    fn fill(&mut self, offset: usize, count: usize, pixel: &[u8]) {
        let length = count
            .checked_mul(pixel.len())
            .expect("validated pixel count");
        match self {
            Self::Memory(bytes) => {
                let row = &mut bytes[offset..offset + length];
                if row.is_empty() {
                    return;
                }
                row[..pixel.len()].copy_from_slice(pixel);
                let mut written = pixel.len();
                // LOOP_PROOF: mode=bounded; reason=Each copy at least doubles initialized bytes until the finite row is filled.;
                while written < length {
                    let take = written.min(length - written);
                    row.copy_within(..take, written);
                    written += take;
                }
            }
            Self::Scanout(mapping) => mapping
                .region_mut(offset, length)
                .expect("validated pixel span")
                .fill(pixel)
                .expect("whole pixels in drawing span"),
        }
    }
    fn read(&self, offset: usize, output: &mut [u8]) {
        match self {
            Self::Memory(bytes) => output.copy_from_slice(&bytes[offset..offset + output.len()]),
            Self::Scanout(mapping) => mapping
                .read(offset, output)
                .expect("validated readback span"),
        }
    }
    fn copy_within(&mut self, source: core::ops::Range<usize>, destination: usize) {
        match self {
            Self::Memory(bytes) => bytes.copy_within(source, destination),
            Self::Scanout(mapping) => mapping
                .copy_within(source, destination)
                .expect("clipped copy spans"),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PerfStats {
    pub flushes: usize,
    pub pixels_drawn: usize,
    pub rectangles_drawn: usize,
}

pub struct Framebuffer {
    pixels: PixelBuffer,
    info: FramebufferLayout,
    back_buffer: Option<Vec<u32>>,
    clip: Rect,
    scratch_u8: Vec<u8>,
    dirty_rects: [Option<Rect>; 4],
    pub stats: PerfStats,
}

impl Framebuffer {
    /// Allocates row workspace before publication. Failure drops the unpublished
    /// destination owner; no draw, register access or mapping change is performed.
    ///
    /// # Errors
    /// Returns `BufferTooSmall` before accessing the destination, or
    /// `OutOfMemory` when the per-row workspace cannot be reserved.
    pub fn new(info: FramebufferLayout, pixels: PixelBuffer) -> Result<Self, FramebufferError> {
        if pixels.len() < info.size() {
            return Err(FramebufferError::BufferTooSmall);
        }
        let row = info.width() as usize * 4;
        let mut scratch_u8 = Vec::new();
        scratch_u8
            .try_reserve_exact(row)
            .map_err(|_| FramebufferError::OutOfMemory)?;
        scratch_u8.resize(row, 0);
        Ok(Self {
            pixels,
            info,
            back_buffer: None,
            clip: Rect::new(0, 0, info.width(), info.height()),
            scratch_u8,
            dirty_rects: [None; 4],
            stats: PerfStats::default(),
        })
    }
    pub fn info(&self) -> &FramebufferLayout {
        &self.info
    }
    pub fn width(&self) -> u32 {
        self.info.width()
    }
    pub fn height(&self) -> u32 {
        self.info.height()
    }
    pub fn stride(&self) -> u32 {
        self.info.stride()
    }
    /// Releases rendering state and transfers its destination to the caller.
    pub fn into_pixels(self) -> PixelBuffer {
        self.pixels
    }
    /// Borrows the complete retained scanout destination for a synchronous batch.
    /// Offscreen RAM remains an ordinary owned Vec and has no device capability.
    pub(crate) fn scanout_region(&mut self) -> Option<hal::scanout::ScanoutRegion<'_>> {
        match &mut self.pixels {
            PixelBuffer::Scanout(mapping) => Some(
                mapping
                    .region_mut(0, self.info.size())
                    .expect("validated complete plane"),
            ),
            PixelBuffer::Memory(_) => None,
        }
    }
    pub fn set_clip(&mut self, rect: Rect) {
        self.clip =
            bounded_intersection(rect, Rect::new(0, 0, self.info.width(), self.info.height()))
                .unwrap_or(Rect::new(0, 0, 0, 0));
    }
    pub fn reset_clip(&mut self) {
        self.clip = Rect::new(0, 0, self.info.width(), self.info.height());
    }
    pub fn clip_rect(&self) -> Rect {
        self.clip
    }
    fn counted_sfence(&self) {
        mmio::sfence();
    }
    fn drawing_format(&self) -> PixelFormat {
        if self.back_buffer.is_some() {
            PixelFormat::Bgra8888
        } else {
            self.info.format()
        }
    }
    /// # Errors
    /// Returns `OutOfMemory` without replacing an existing back plane.
    pub fn enable_double_buffering(&mut self) -> Result<(), FramebufferError> {
        let count = self.info.width() as usize * self.info.height() as usize;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(count)
            .map_err(|_| FramebufferError::OutOfMemory)?;
        bytes.resize(count, 0);
        self.enable_double_buffering_from_vec(bytes)
    }
    /// # Errors
    /// Rejects a pixel count unequal to the complete plane and retains any
    /// existing back plane. The supplied buffer is consumed on both outcomes.
    pub fn enable_double_buffering_from_vec(
        &mut self,
        pixels: Vec<u32>,
    ) -> Result<(), FramebufferError> {
        if pixels.len() != self.info.width() as usize * self.info.height() as usize {
            return Err(FramebufferError::BufferTooSmall);
        }
        self.back_buffer = Some(pixels);
        Ok(())
    }
    pub fn is_double_buffered(&self) -> bool {
        self.back_buffer.is_some()
    }
    pub fn set_pixel(&mut self, x: i32, y: i32, color: Color) {
        if !self.clip.contains(Point::new(x, y)) {
            return;
        }
        self.mark_dirty(Rect::new(x, y, 1, 1));
        self.set_pixel_raw(x, y, color);
        self.counted_sfence();
    }
    pub(super) fn set_pixel_raw(&mut self, x: i32, y: i32, color: Color) {
        if x < 0 || y < 0 || x as u32 >= self.info.width() || y as u32 >= self.info.height() {
            return;
        }
        if let Some(back) = self.back_buffer.as_mut() {
            back[y as usize * self.info.width() as usize + x as usize] = color.to_u32();
        } else {
            let mut bytes = [0; 4];
            self.info.format().encode_color_bytes(color, &mut bytes);
            let width = self.info.format().bytes_per_pixel();
            self.pixels.write(
                y as usize * self.info.stride() as usize + x as usize * width,
                &bytes[..width],
            );
        }
    }
    pub fn get_pixel(&self, x: u32, y: u32) -> Color {
        if x >= self.info.width() || y >= self.info.height() {
            return Color::BLACK;
        }
        if let Some(back) = self.back_buffer.as_ref() {
            return Color::from_u32(back[y as usize * self.info.width() as usize + x as usize]);
        }
        let mut bytes = [0; 4];
        let width = self.info.format().bytes_per_pixel();
        self.pixels.read(
            y as usize * self.info.stride() as usize + x as usize * width,
            &mut bytes[..width],
        );
        self.info.format().decode_color_bytes(&bytes)
    }
    pub fn clear(&mut self, color: Color) {
        let original_clip = self.clip;
        self.reset_clip();
        self.fill_rect(
            Rect::new(0, 0, self.info.width(), self.info.height()),
            color,
        );
        self.clip = original_clip;
    }
    fn color_to_rgb565(color: Color) -> u16 {
        ((color.red as u16 >> 3) << 11)
            | ((color.green as u16 >> 2) << 5)
            | (color.blue as u16 >> 3)
    }
    fn write_u32_run(&mut self, offset: usize, count: usize, color: u32) {
        if let Some(back) = self.back_buffer.as_mut() {
            let first = offset / 4;
            back[first..first + count].fill(color);
        } else {
            self.pixels.fill(offset, count, &color.to_le_bytes());
        }
    }
    fn color_bytes_24(&self, color: Color) -> (u8, u8, u8) {
        let mut bytes = [0; 4];
        self.info.format().encode_color_bytes(color, &mut bytes);
        (bytes[0], bytes[1], bytes[2])
    }
    fn write_bgr_run(&mut self, offset: usize, count: usize, color: Color) {
        let mut pixel = [0; 4];
        self.info.format().encode_color_bytes(color, &mut pixel);
        self.pixels.fill(offset, count, &pixel[..3]);
    }
    fn write_u16_run_streaming_nofence(&mut self, offset: usize, count: usize, color: u16) {
        self.pixels.fill(offset, count, &color.to_le_bytes());
    }
    fn write_glyph_row_32bit_nofence(
        &mut self,
        bits: u8,
        offset: usize,
        foreground: u32,
        background: u32,
    ) -> bool {
        let row: [u32; 8] = core::array::from_fn(|column| {
            if bits & (0x80 >> column) != 0 {
                foreground
            } else {
                background
            }
        });
        if let Some(back) = self.back_buffer.as_mut() {
            back[offset / 4..offset / 4 + 8].copy_from_slice(&row);
            false
        } else {
            let mut bytes = [0; 32];
            // LOOP_PROOF: mode=bounded; reason=The glyph row contains exactly eight pixels.;
            for (pixel, output) in row.iter().zip(bytes.chunks_exact_mut(4)) {
                output.copy_from_slice(&pixel.to_le_bytes());
            }
            self.pixels.write(offset, &bytes);
            true
        }
    }
    /// Bounding rectangle covering all pending drawing updates.
    pub fn dirty_rect(&self) -> Option<Rect> {
        let mut out: Option<Rect> = None;
        for slot in self.dirty_rects.iter() {
            if let Some(r) = slot {
                out = Some(match out {
                    None => *r,
                    Some(prev) => prev.union(r),
                });
            }
        }
        out
    }

    /// 描画領域を「汚れ」としてマーク
    /// Uses up to 4 disjoint rects; merges when full to avoid over-expanding.
    /// All slots full: find the pair of dirty rects whose merge adds the least area.
    fn find_best_merge_pair(rects: &[Option<Rect>; 4]) -> (usize, usize) {
        let mut min_added_area = u64::MAX;
        let mut merge_pair = (0, 1);
        for i in 0..4 {
            for j in (i + 1)..4 {
                if let (Some(a), Some(b)) = (&rects[i], &rects[j]) {
                    let area_a = a.width as u64 * a.height as u64;
                    let area_b = b.width as u64 * b.height as u64;
                    let combined = a.union(b);
                    let combined_area = combined.width as u64 * combined.height as u64;
                    let added_area = combined_area.saturating_sub(area_a + area_b);
                    if added_area < min_added_area {
                        min_added_area = added_area;
                        merge_pair = (i, j);
                    }
                }
            }
        }
        merge_pair
    }

    /// Try to merge rect with an existing dirty rect, or insert into an empty slot.
    /// Returns true if successfully placed.
    fn try_merge_or_insert_dirty(&mut self, draw_rect: Rect) -> bool {
        for slot in self.dirty_rects.iter_mut() {
            if let Some(existing) = slot {
                let merged = existing.union(&draw_rect);
                let existing_area = existing.width as u64 * existing.height as u64;
                let draw_area = draw_rect.width as u64 * draw_rect.height as u64;
                let merged_area = merged.width as u64 * merged.height as u64;

                if merged_area <= (existing_area + draw_area) * 3 / 2 {
                    *slot = Some(merged);
                    return true;
                }
            }
        }

        for slot in self.dirty_rects.iter_mut() {
            if slot.is_none() {
                *slot = Some(draw_rect);
                return true;
            }
        }

        false
    }

    fn mark_dirty(&mut self, rect: Rect) {
        // クリップ領域との共通部分をとる
        let draw_rect = match bounded_intersection(rect, self.clip) {
            Some(r) => r,
            None => return,
        };

        if !draw_rect.is_valid() {
            return;
        }

        if self.try_merge_or_insert_dirty(draw_rect) {
            return;
        }

        // All slots full: force merge the two rects with smallest area INCREASE
        let (i, j) = Self::find_best_merge_pair(&self.dirty_rects);
        if let (Some(a), Some(b)) = (&self.dirty_rects[i], &self.dirty_rects[j]) {
            let merged = a.union(b);
            self.dirty_rects[i] = Some(merged);
            self.dirty_rects[j] = Some(draw_rect);
        }
    }

    /// 最適化されたバッファ転送 - transfers all dirty rects
    pub fn flush_dirty_area(&mut self) {
        // Extract rects to stack to avoid borrowing self.dirty_rects while calling self.blit_rect
        let mut rects = [None; 4];
        for (i, slot) in self.dirty_rects.iter_mut().enumerate() {
            rects[i] = slot.take();
        }

        for rect_opt in rects.iter() {
            if let Some(rect) = rect_opt {
                self.stats.flushes += 1;
                self.blit_rect(*rect);
            }
        }
    }

    /// バックバッファをフロントにコピー（全画面または汚れた部分）
    pub fn swap_buffers(&mut self) {
        if self.back_buffer.is_some() {
            self.flush_dirty_area();
        }
    }

    /// Converts only dirty rows into the retained front plane. Workspace is
    /// reserved at construction; repeated drawing and flush never grow it.
    pub fn blit_rect(&mut self, rect: Rect) {
        let Some(back) = self.back_buffer.as_ref() else {
            return;
        };
        let Some(rect) =
            bounded_intersection(rect, Rect::new(0, 0, self.info.width(), self.info.height()))
        else {
            return;
        };
        let bpp = self.info.format().bytes_per_pixel();
        let width = rect.width as usize;
        // LOOP_PROOF: mode=bounded; reason=The clipped rectangle has a finite row count within the validated plane.;
        for y in rect.y as usize..rect.y as usize + rect.height as usize {
            let start = y * self.info.width() as usize + rect.x as usize;
            let row = &back[start..start + width];
            super::packer::pack_backbuffer(
                row,
                &mut self.scratch_u8[..width * bpp],
                self.info.format(),
            );
            self.pixels.write(
                y * self.info.stride() as usize + rect.x as usize * bpp,
                &self.scratch_u8[..width * bpp],
            );
        }
        self.counted_sfence();
    }
}

/// Uses widened edges before intersecting public rectangles, so overflowing
/// caller coordinates never escape the validated drawing plane.
fn bounded_intersection(a: Rect, b: Rect) -> Option<Rect> {
    let x = i64::from(a.x).max(i64::from(b.x));
    let y = i64::from(a.y).max(i64::from(b.y));
    let right = (i64::from(a.x) + i64::from(a.width)).min(i64::from(b.x) + i64::from(b.width));
    let bottom = (i64::from(a.y) + i64::from(a.height)).min(i64::from(b.y) + i64::from(b.height));
    if x >= right || y >= bottom {
        return None;
    }
    Some(Rect::new(
        x as i32,
        y as i32,
        (right - x) as u32,
        (bottom - y) as u32,
    ))
}

mod drawing;
mod image;
#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests;
#[cfg(test)]
mod tests;
mod text;
