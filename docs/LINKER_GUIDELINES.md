# Linker Guidelines & Safety Checks

- Status: Canonical build safety note
- Audience: ビルド設定、target JSON、CI を触る contributor
- Related: [ドキュメントハブ](README.md), [アーキテクチャ概要](ARCHITECTURE.md), [カーネルブートシーケンス](kernel_boot_sequence.md)

This document explains the recommended configuration for the kernel linker script and CI checks to avoid file-offset collisions ("section overlaps").

Why this matters

- Overlapping file offsets (for example, `.text` overlapping `.shstrtab`) cause linker failures or corrupted kernels.
- Common cause: duplicating `-T` (linker script) flags between the target JSON and `.cargo/config.toml` (or environment `RUSTFLAGS`). Use a single source of truth.

Rules

- Specify the linker script only in the target JSON (`pre-link-args` / `-Tkernel/linker.ld`). Do NOT also set it via `.cargo/config.toml` or `RUSTFLAGS`.
- Avoid passing `-Wl,` style prefixed linker flags through `RUSTFLAGS` when using the `rust-lld` driver; pass linker args directly via `-C link-arg=...`.

Automated checks (CI)

- CI runs `scripts/check_linker_layout.py` after building the kernel to detect overlapping section file ranges and fails when it finds issues.
- CI also checks `.cargo/config.toml` for accidental `-C link-arg=-Tlinker.ld` duplicates and fails if found.

Local troubleshooting

- To reproduce the linker's final file layout locally, run the build with extra verbosity and inspect the map file or use `scripts/check_linker_layout.py` on the produced binary:

  python scripts/check_linker_layout.py target/x86_64-exorust/debug/exorust_kernel

- If you need linker verbose logs for diagnosis, prefer passing `-C link-arg=--verbose` to `RUSTFLAGS` (or invoke the platform-native `ld.lld` / `lld-link` directly). Do not use `-Wl,--verbose` when using `rust-lld`.

If you find a regression

- Check for duplicate `-T` flags in `target` JSON and `.cargo/config.toml`.
- Run `scripts/check_linker_layout.py` against the built binary and share its output along with the verbose linker log and `kernel.map` file.

## 関連文書

- [README.md](README.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [kernel_boot_sequence.md](kernel_boot_sequence.md)
