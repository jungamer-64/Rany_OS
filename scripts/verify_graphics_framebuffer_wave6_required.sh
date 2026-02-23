#!/usr/bin/env bash
set -euo pipefail

# Validates that Wave6 graphics/framebuffer deterministic Phase A/B + bench exports
# are wired into suite_kernel as required checks.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FB_EXPORT_ROOT="$ROOT_DIR/kernel/src/graphics/framebuffer/qemu_tests"
FB_EXPORT_FILE="$ROOT_DIR/kernel/src/graphics/framebuffer/qemu_tests.rs"
PACKER_FILE="$ROOT_DIR/kernel/src/graphics/packer.rs"
KERNEL_WRAPPER_ROOT="$ROOT_DIR/kernel/src/qemu_tests"
KERNEL_WRAPPER_FILE="$ROOT_DIR/kernel/src/qemu_tests.rs"
KERNEL_SUITE_ROOT="$ROOT_DIR/qemu-suites/kernel/src"
PENDING_FILE="$ROOT_DIR/scripts/qemu_pending_cases.lst"

for required_file in \
  "$FB_EXPORT_ROOT" \
  "$FB_EXPORT_FILE" \
  "$PACKER_FILE" \
  "$KERNEL_WRAPPER_ROOT" \
  "$KERNEL_WRAPPER_FILE" \
  "$KERNEL_SUITE_ROOT" \
  "$PENDING_FILE"
do
  if [[ ! -e "$required_file" ]]; then
    echo "[verify_graphics_framebuffer_wave6_required] missing file: $required_file" >&2
    exit 1
  fi
done

cases=(
  "draw_image_32bit_bgra_backbuffer"
  "draw_image_24bit_bgr_backbuffer"
  "write_bgr_run_small_mmio"
  "write_bgr_run_large_mmio_full"
  "write_bgr_run_large_mmio_full_unaligned"
  "write_bgr_run_small_mmio_pairs_aligned"
  "write_bgr_run_small_mmio_generic_unaligned"
  "draw_hline_32bit_backbuffer"
  "draw_text_space_32bit_backbuffer"
  "draw_line_matches_naive_32bit_backbuffer"
  "draw_line_matches_naive_24bit_backbuffer"
  "draw_text_space_24bit_backbuffer"
  "draw_image_32bit_mmio"
  "draw_image_24bit_mmio"
  "draw_image_32bit_mmio_rgba"
  "write_bytes_mmio_alignment"
  "write_opaque_run_24bit_even_odd_mmio"
  "pack_rgba_to_bgra_basic"
  "pack_rgba_to_bgra_scalar_random"
  "draw_image_bgra_stream_matches_backbuffer"
  "fill_rect_32bit_mmio"
  "dirty_rect_tracking"
  "dirty_rect_flush_only_marked_area"
  "draw_text_partial_left_clip_32bit_backbuffer"
)

violations=0

if ! rg -q "graphics_framebuffer_wave6_phase_a_exports" "$KERNEL_SUITE_ROOT"; then
  echo "[verify_graphics_framebuffer_wave6_required] missing wave6 phase A suite entry under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

if ! rg -q "graphics_framebuffer_wave6_phase_b_exports" "$KERNEL_SUITE_ROOT"; then
  echo "[verify_graphics_framebuffer_wave6_required] missing wave6 phase B suite entry under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

if ! rg -q "graphics_framebuffer_wave6_bench_exports" "$KERNEL_SUITE_ROOT"; then
  echo "[verify_graphics_framebuffer_wave6_required] missing wave6 bench suite entry under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

if ! rg -q "pub fn qemu_test_set_packer_mode_override\\(" "$PACKER_FILE"; then
  echo "[verify_graphics_framebuffer_wave6_required] missing qemu hook 'qemu_test_set_packer_mode_override' in ${PACKER_FILE#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

if ! rg -q "pub fn qemu_test_clear_packer_mode_override\\(" "$PACKER_FILE"; then
  echo "[verify_graphics_framebuffer_wave6_required] missing qemu hook 'qemu_test_clear_packer_mode_override' in ${PACKER_FILE#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

if rg -q "test_packer_env_override" "$PENDING_FILE"; then
  echo "[verify_graphics_framebuffer_wave6_required] env override legacy case still listed in ${PENDING_FILE#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

for case_name in "${cases[@]}"; do
  export_fn="wave6_${case_name}_smoke"
  wrapper_fn="graphics_wave6_${case_name}_smoke"

  if ! rg -q "pub fn ${export_fn}\\(" "$FB_EXPORT_FILE" "$FB_EXPORT_ROOT"; then
    echo "[verify_graphics_framebuffer_wave6_required] missing export '${export_fn}' under kernel/src/graphics/framebuffer/qemu_tests*"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${wrapper_fn}\\(" "$KERNEL_WRAPPER_FILE" "$KERNEL_WRAPPER_ROOT"; then
    echo "[verify_graphics_framebuffer_wave6_required] missing wrapper '${wrapper_fn}' under kernel/src/qemu_tests*"
    violations=$((violations + 1))
  fi

  if ! rg -q "${wrapper_fn}" "$KERNEL_SUITE_ROOT"; then
    echo "[verify_graphics_framebuffer_wave6_required] missing suite wiring '${wrapper_fn}' under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if rg -q "${case_name}" "$PENDING_FILE"; then
    echo "[verify_graphics_framebuffer_wave6_required] promoted case '${case_name}' still listed in ${PENDING_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
done

bench_cases=(
  "draw_image_bulk"
  "draw_image_24bit_bulk"
  "draw_image_rgba_bulk"
  "draw_hline_bulk"
  "draw_text_bulk"
)

phase_b_cases=(
  "write_bgr_run_large_mmio"
  "write_bgr_run_large"
  "draw_image_24bit_rgb888_backbuffer"
  "draw_hline_24bit_rgb888_mmio"
  "pack_rgba_to_bgra_ssse3_matches_scalar"
  "pack_rgba_to_bgra_avx2_matches_scalar"
  "pack_rgba_to_bgr24_avx2_matches_scalar"
  "pack_rgba_to_bgr24_ssse3_matches_scalar"
  "pack_rgba_to_bgra_neon_matches_scalar"
  "pack_rgba_to_bgr24_neon_matches_scalar"
  "pack_rgba_to_bgr24_neon_matches_scalar_rgb"
  "packer_env_override_no_std"
)

for case_name in "${phase_b_cases[@]}"; do
  export_fn="wave6_${case_name}_smoke"
  wrapper_fn="graphics_wave6_${case_name}_smoke"

  if ! rg -q "pub fn ${export_fn}\\(" "$FB_EXPORT_FILE" "$FB_EXPORT_ROOT"; then
    echo "[verify_graphics_framebuffer_wave6_required] missing export '${export_fn}' under kernel/src/graphics/framebuffer/qemu_tests*"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${wrapper_fn}\\(" "$KERNEL_WRAPPER_FILE" "$KERNEL_WRAPPER_ROOT"; then
    echo "[verify_graphics_framebuffer_wave6_required] missing wrapper '${wrapper_fn}' under kernel/src/qemu_tests*"
    violations=$((violations + 1))
  fi

  if ! rg -q "${wrapper_fn}" "$KERNEL_SUITE_ROOT"; then
    echo "[verify_graphics_framebuffer_wave6_required] missing suite wiring '${wrapper_fn}' under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if rg -q "${case_name}" "$PENDING_FILE"; then
    echo "[verify_graphics_framebuffer_wave6_required] promoted case '${case_name}' still listed in ${PENDING_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
done

for case_name in "${bench_cases[@]}"; do
  export_fn="wave6_bench_${case_name}_smoke"
  wrapper_fn="graphics_wave6_bench_${case_name}_smoke"
  pending_case="bench_${case_name}"

  if ! rg -q "pub fn ${export_fn}\(" "$FB_EXPORT_FILE" "$FB_EXPORT_ROOT"; then
    echo "[verify_graphics_framebuffer_wave6_required] missing export '${export_fn}' under kernel/src/graphics/framebuffer/qemu_tests*"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${wrapper_fn}\(" "$KERNEL_WRAPPER_FILE" "$KERNEL_WRAPPER_ROOT"; then
    echo "[verify_graphics_framebuffer_wave6_required] missing wrapper '${wrapper_fn}' under kernel/src/qemu_tests*"
    violations=$((violations + 1))
  fi

  if ! rg -q "${wrapper_fn}" "$KERNEL_SUITE_ROOT"; then
    echo "[verify_graphics_framebuffer_wave6_required] missing suite wiring '${wrapper_fn}' under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if rg -q "${pending_case}" "$PENDING_FILE"; then
    echo "[verify_graphics_framebuffer_wave6_required] promoted bench case '${pending_case}' still listed in ${PENDING_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
done

if ! rg -q "Graphics/Framebuffer Wave6 bench deterministic set is promoted to required suite_kernel" "$PENDING_FILE"; then
  echo "[verify_graphics_framebuffer_wave6_required] missing Wave6 bench promotion marker in ${PENDING_FILE#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

if ! rg -q "Graphics/Framebuffer Wave6 residual \(bench only\): none" "$PENDING_FILE"; then
  echo "[verify_graphics_framebuffer_wave6_required] missing Wave6 bench residual-none marker in ${PENDING_FILE#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

if [[ "$violations" -gt 0 ]]; then
  echo "[verify_graphics_framebuffer_wave6_required] FAIL: found $violations issues"
  exit 1
fi

echo "[verify_graphics_framebuffer_wave6_required] PASS"
