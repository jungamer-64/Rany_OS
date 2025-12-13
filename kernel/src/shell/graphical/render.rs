// ============================================================================
// src/shell/graphical/render.rs - Graphical Shell Rendering
// ============================================================================
//
// This module implements the rendering pipeline for the graphical shell.
//
// Key design patterns:
// - RenderContext: Bundles framebuffer, state, and resources for drawing.
// - Layout: Pre-computes coordinates for consistent positioning.
// - Culling: Each drawing function skips work outside the clip region.
//
// Type safety notes:
// - All screen coordinates use i32 (allows off-screen negative values).
// - Line indices use usize (always non-negative array indices).
// - Integer division is protected by checked_div or explicit zero checks.
//
// ============================================================================

#![allow(dead_code)]

use super::shell::GraphicalShell;
use super::types::{ShellResources, ShellState};
use super::utils::RectList;
use crate::graphics::{Color, Framebuffer, Rect};

/// Maximum number of completions to display at once.
const COMPLETION_LIMIT: usize = 5;

/// Screen coordinate type alias for documentation clarity.
///
/// Uses i32 to allow negative values for off-screen elements.
/// This matches `Rect`'s x/y field types.
type ScreenCoord = i32;

/// Line index type alias for documentation clarity.
///
/// Always non-negative, used for array indexing.
type LineIndex = usize;

// ============================================================================
// Layout
// ============================================================================

/// Pre-computed layout coordinates for rendering.
///
/// All coordinate values use `ScreenCoord` (i32):
/// - Allows negative values during calculations
/// - Matches `Rect`'s x/y coordinate type
/// - Eliminates constant casting between types
#[derive(Clone, Copy)]
struct Layout {
    /// Y coordinate of the input line
    input_y: ScreenCoord,
    /// Font height in pixels
    font_h: ScreenCoord,
    /// Font width in pixels
    font_w: ScreenCoord,
    /// Framebuffer width in pixels
    fb_width: ScreenCoord,
    /// Framebuffer height in pixels
    fb_height: ScreenCoord,
    /// Y coordinate for completion suggestions (None if hidden)
    completion_y: Option<ScreenCoord>,
}

impl Layout {
    /// Computes layout based on current shell state and resources.
    #[must_use]
    fn compute(state: &ShellState, res: &ShellResources) -> Self {
        let input_y = res.input_line_y();
        let font_h = res.font_height();
        let fb_width = res.fb_width as ScreenCoord;
        let fb_height = res.fb_height as ScreenCoord;

        // Find a valid Y position for completions (prefer below input, fallback to above).
        let completion_y = (!state.temp_fmt_buffer.is_empty())
            .then(|| {
                [input_y + font_h, input_y - font_h]
                    .into_iter()
                    .find(|&y| y >= 0 && y + font_h <= fb_height)
            })
            .flatten();

        Self {
            input_y,
            font_h,
            font_w: res.font.width() as ScreenCoord,
            fb_width,
            fb_height,
            completion_y,
        }
    }
}

// ============================================================================
// RenderContext
// ============================================================================

/// Context for rendering a single frame or partial update.
///
/// Bundles mutable framebuffer access with immutable state and resources,
/// enabling a clean separation of concerns.
struct RenderContext<'a, 'b> {
    fb: &'a mut Framebuffer,
    state: &'b ShellState,
    res: &'b ShellResources,
    layout: Layout,
    /// Current clip rectangle for culling decisions
    clip: Rect,
}

impl<'a, 'b> RenderContext<'a, 'b> {
    fn new(fb: &'a mut Framebuffer, state: &'b ShellState, res: &'b ShellResources) -> Self {
        Self::with_layout(fb, state, res, Layout::compute(state, res))
    }

    fn with_layout(
        fb: &'a mut Framebuffer,
        state: &'b ShellState,
        res: &'b ShellResources,
        layout: Layout,
    ) -> Self {
        Self {
            fb,
            state,
            res,
            layout,
            clip: Rect::default(),
        }
    }

    /// Executes the full render pipeline for the given clip rectangle.
    fn run_pipeline(&mut self, clip_rect: Rect) {
        if clip_rect.width == 0 || clip_rect.height == 0 {
            return;
        }

        self.clip = clip_rect;
        self.fb.set_clip(clip_rect);

        // Draw all layers in order (no method chaining for better flexibility)
        self.draw_background();
        self.draw_output_lines();
        self.draw_input_line();
        self.draw_text_cursor();
        self.draw_completions();
        self.draw_mouse_cursor();

        self.fb.blit_rect(clip_rect);
        self.fb.reset_clip();
    }

    /// Fills only the clip region with the background color.
    fn draw_background(&mut self) {
        self.fb.fill_rect(self.clip, self.res.theme.background);
    }

    /// Draws visible output lines with scrolling support and culling.
    fn draw_output_lines(&mut self) {
        let Layout {
            font_h,
            fb_height,
            fb_width,
            ..
        } = self.layout;
        let theme = &self.res.theme;

        // SAFETY: font_h must be positive for division
        // Use checked_div for belt-and-suspenders safety
        let Some(lines_on_screen) = fb_height.checked_div(font_h) else {
            debug_assert!(font_h > 0, "font_h must be positive, got {}", font_h);
            return;
        };

        // Calculate maximum visible lines (leaving room for input line at bottom)
        let max_visible: LineIndex = (lines_on_screen - 2).max(0) as LineIndex;
        if max_visible == 0 {
            return;
        }

        // Output area spans from Y=0 to Y=(max_visible * font_h)
        let output_area_height: ScreenCoord = (max_visible as i32) * font_h;
        let output_area = Rect::new(0, 0, fb_width as u32, output_area_height as u32);

        // CULL: If clip doesn't intersect output area at all, skip entirely
        if !self.clip.intersects(&output_area) {
            return;
        }

        // RANGE OPTIMIZATION: Calculate which screen-relative line indices intersect the clip
        // Clamp to non-negative to prevent underflow when casting to usize
        let clip_top: ScreenCoord = self.clip.y.max(0);
        let clip_bottom: ScreenCoord = self.clip.bottom().min(output_area_height);

        // Safe line index calculation using checked_div
        // If font_h is 0, we already returned above, but this is belt-and-suspenders
        let start_line: LineIndex = (clip_top / font_h) as LineIndex;
        let end_line: LineIndex = clip_bottom
            .saturating_sub(1)
            .checked_div(font_h)
            .map(|v| v as LineIndex)
            .unwrap_or(0);

        // Clamp to valid range [0, max_visible - 1]
        let (start_line, end_line): (LineIndex, LineIndex) = (
            start_line.min(max_visible.saturating_sub(1)),
            end_line.min(max_visible.saturating_sub(1)),
        );

        // Ensure start <= end (could happen with edge cases)
        if start_line > end_line {
            return;
        }

        // skip_count: how many lines to skip from the output_lines history (for scrolling)
        let skip_count = self
            .state
            .output_lines
            .len()
            .saturating_sub(max_visible + self.state.scroll_offset);

        // Only iterate over lines in the culled range
        self.state
            .output_lines
            .iter()
            .skip(skip_count + start_line)
            .take(end_line - start_line + 1)
            .enumerate()
            .for_each(|(i, line)| {
                // i is relative to start_line, so actual screen Y = (start_line + i) * font_h
                let y = ((start_line + i) as i32) * font_h;
                self.res.font.draw_string(
                    self.fb,
                    0,
                    y,
                    &line.text,
                    line.color,
                    Some(theme.background),
                );
            });
    }

    /// Draws the prompt and current input buffer with culling.
    fn draw_input_line(&mut self) {
        let Layout {
            input_y,
            font_h,
            fb_width,
            ..
        } = self.layout;
        let input_rect = Rect::new(0, input_y, fb_width as u32, font_h as u32);

        // CULL: Early return if clip doesn't intersect input line
        if !self.clip.intersects(&input_rect) {
            return;
        }

        let theme = &self.res.theme;
        let font = &self.res.font;

        font.draw_string(
            self.fb,
            0,
            input_y,
            &self.state.prompt,
            theme.prompt,
            Some(theme.background),
        );
        font.draw_string(
            self.fb,
            self.state.cached_prompt_end_x,
            input_y,
            &self.state.input_buffer.content,
            theme.input,
            Some(theme.background),
        );
    }

    /// Draws the blinking text cursor with culling.
    fn draw_text_cursor(&mut self) {
        if !self.state.cursor_visible {
            return;
        }

        let Layout {
            input_y,
            font_w,
            font_h,
            fb_width,
            ..
        } = self.layout;
        let cursor_x = self.state.cursor_x();
        if cursor_x >= fb_width {
            return;
        }

        let cursor_rect = Rect::new(cursor_x, input_y, font_w as u32, font_h as u32);

        // CULL: Early return if clip doesn't intersect cursor
        if !self.clip.intersects(&cursor_rect) {
            return;
        }

        self.fb.fill_rect(cursor_rect, self.res.theme.cursor);

        let c = self.state.cached_cursor_char.unwrap_or(' ');
        self.res.font.draw_char(
            self.fb,
            cursor_x,
            input_y,
            c,
            self.res.theme.background,
            None,
        );
    }

    /// Draws the completion suggestions line with culling.
    fn draw_completions(&mut self) {
        let Some(y) = self.layout.completion_y else {
            return;
        };

        let comp_rect = Rect::new(0, y, self.layout.fb_width as u32, self.layout.font_h as u32);

        // CULL: Early return if clip doesn't intersect completion area
        if !self.clip.intersects(&comp_rect) {
            return;
        }

        self.res.font.draw_string(
            self.fb,
            0,
            y,
            &self.state.temp_fmt_buffer,
            self.res.theme.info,
            Some(self.res.theme.background),
        );
    }

    /// Draws a simple crosshair mouse cursor with culling.
    fn draw_mouse_cursor(&mut self) {
        if !self.state.show_mouse_cursor {
            return;
        }

        let (mx, my) = (self.state.mouse.x, self.state.mouse.y);

        // CULL: Early return if clip doesn't intersect mouse cursor area
        const CROSSHAIR_SIZE: i32 = 2;
        let mouse_rect = Rect::new(
            mx - CROSSHAIR_SIZE,
            my - CROSSHAIR_SIZE,
            (CROSSHAIR_SIZE * 2 + 1) as u32,
            (CROSSHAIR_SIZE * 2 + 1) as u32,
        );
        if !self.clip.intersects(&mouse_rect) {
            return;
        }

        (-CROSSHAIR_SIZE..=CROSSHAIR_SIZE).for_each(|offset| {
            self.fb.set_pixel(mx + offset, my, Color::WHITE);
            self.fb.set_pixel(mx, my + offset, Color::WHITE);
        });
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Formats completion suggestions into a display buffer.
///
/// Uses `push_str` instead of `write!` macro to avoid the overhead
/// of the `fmt::Write` trait (which involves vtable dispatch).
fn format_completions(
    buf: &mut crate::alloc::string::String,
    comps: &[crate::alloc::string::String],
    index: usize,
) {
    buf.push_str("  ");

    for (i, comp) in comps.iter().take(COMPLETION_LIMIT).enumerate() {
        if i == index {
            buf.push('{');
            buf.push_str(comp);
            buf.push('}');
        } else {
            buf.push_str(comp);
        }
        buf.push(' ');
    }

    let remaining = comps.len().saturating_sub(COMPLETION_LIMIT);
    if remaining > 0 {
        buf.push_str("... (+");
        // Simple integer to string conversion (avoids fmt machinery)
        push_usize(buf, remaining);
        buf.push(')');
    }
}

/// Appends a usize to a string buffer without using fmt::Write.
///
/// This is a micro-optimization to avoid the formatting machinery
/// overhead in tight loops. For small numbers (typical completion counts),
/// this is effectively O(1).
#[inline]
fn push_usize(buf: &mut crate::alloc::string::String, mut n: usize) {
    if n == 0 {
        buf.push('0');
        return;
    }

    // Stack buffer for digits (max 20 digits for u64)
    let mut digits = [0u8; 20];
    let mut i = 0;

    while n > 0 {
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }

    // Push digits in reverse order
    while i > 0 {
        i -= 1;
        buf.push(digits[i] as char);
    }
}

// ============================================================================
// GraphicalShell Rendering API
// ============================================================================

impl GraphicalShell {
    // --- Public API ---

    /// Performs a full screen redraw.
    pub fn redraw(&mut self, fb: &mut Framebuffer) {
        self.perform_draw(fb, |shell| {
            RectList::<1>::from_element(Rect::new(
                0,
                0,
                shell.resources.fb_width,
                shell.resources.fb_height,
            ))
        });
    }

    /// Redraws only the cursor region (for blink updates).
    pub fn redraw_cursor_only(&mut self, fb: &mut Framebuffer) {
        self.perform_draw(fb, |shell| {
            RectList::<1>::from_element(shell.current_cursor_rect())
        });
    }

    /// Redraws the input line and completion window.
    pub fn redraw_input_line(&mut self, fb: &mut Framebuffer) {
        self.perform_draw(fb, |shell| {
            let layout = Layout::compute(&shell.state, &shell.resources);
            let new_comp = shell.completion_rect_from_layout(&layout);
            let old_comp = shell.state.last_completion_rect;
            let input_rect = shell.current_input_line_rect();

            shell.state.last_completion_rect = new_comp;

            // Use RectList::<8> for future expansion (status bar, debug info, etc.)
            // Use push_or_merge to automatically merge overlapping regions
            // (e.g., new_comp and old_comp at the same position → single draw)
            let mut regions = RectList::<8>::new();
            regions.push(input_rect);
            regions.push_or_merge(new_comp);
            regions.push_or_merge(old_comp);
            regions
        });
    }

    /// Alias for `redraw_input_line` (backwards compatibility).
    pub fn redraw_input_only(&mut self, fb: &mut Framebuffer) {
        self.redraw_input_line(fb);
    }

    /// Redraws only the mouse cursor region (optimized for mouse movement).
    ///
    /// This is much faster than `redraw()` because it only updates:
    /// 1. The old mouse position (to restore the background)
    /// 2. The new mouse position (to draw the cursor)
    ///
    /// The two regions are merged if they overlap, further reducing draw calls.
    pub fn redraw_mouse_region(&mut self, fb: &mut Framebuffer, old_rect: Rect) {
        if !self.state.show_mouse_cursor {
            return;
        }

        let new_rect = self.state.mouse_rect();

        // If rects are the same (mouse didn't move), skip
        if old_rect == new_rect {
            return;
        }

        self.perform_draw(fb, |_| {
            let mut regions = RectList::<2>::new();
            regions.push_or_merge(old_rect);
            regions.push_or_merge(new_rect);
            regions
        });
    }

    // --- Private Helpers ---

    /// Template method for all drawing operations.
    ///
    /// **Strategy: Pre-merge mouse region into dirty list**
    ///
    /// Instead of tracking `mouse_drawn` flag during the loop, we merge
    /// the mouse rectangle into the dirty region list BEFORE drawing.
    /// This ensures:
    /// 1. Mouse is never drawn multiple times
    /// 2. Overlapping dirty regions don't overwrite the mouse cursor
    /// 3. No state tracking variables needed in the drawing loop
    fn perform_draw<F, const N: usize>(&mut self, fb: &mut Framebuffer, get_dirty_regions: F)
    where
        F: FnOnce(&mut Self) -> RectList<N>,
    {
        self.prepare_completions_buffer();

        let mut dirty_regions = get_dirty_regions(self);

        // Pre-merge: Add mouse cursor to dirty regions if visible.
        // push_or_merge will automatically merge with overlapping regions.
        if self.state.show_mouse_cursor {
            dirty_regions.push_or_merge(self.state.mouse_rect());
        }

        // Compute Layout ONCE before the loop
        let layout = Layout::compute(&self.state, &self.resources);

        // Simple drawing loop - no mouse_drawn tracking needed
        for dirty in &dirty_regions {
            RenderContext::with_layout(fb, &self.state, &self.resources, layout)
                .run_pipeline(*dirty);
        }

        // Note: swap_buffers removed - we use partial blit_rect only.
        // blit_rect is called inside run_pipeline for each dirty region.
    }

    fn completion_rect_from_layout(&self, layout: &Layout) -> Rect {
        layout
            .completion_y
            .map(|y| Rect::new(0, y, layout.fb_width as u32, layout.font_h as u32))
            .unwrap_or_default()
    }

    fn current_cursor_rect(&self) -> Rect {
        let res = &self.resources;
        Rect::new(
            self.state.cursor_x(),
            res.input_line_y(),
            res.font.width(),
            res.font.height(),
        )
    }

    fn current_input_line_rect(&self) -> Rect {
        let res = &self.resources;
        Rect::new(0, res.input_line_y(), res.fb_width, res.font.height())
    }

    fn prepare_completions_buffer(&mut self) {
        self.state.temp_fmt_buffer.clear();
        if !self.state.completions.is_empty() {
            format_completions(
                &mut self.state.temp_fmt_buffer,
                &self.state.completions,
                self.state.completion_index,
            );
        }
    }
}
