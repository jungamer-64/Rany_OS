# ExoRust ドキュメントハブ

- Status: Canonical document index
- Audience: 設計確認、実装、レビュー、検証のために文書を辿る contributor
- Related: [README.md](../README.md), [設計ハブ](design-hub.md), [archive index](archive/README.md)

このディレクトリは ExoRust の公開文書ハブです。現行の正規文書と、参照資料、Runbook、提案書、履歴資料を分けて案内します。

## Overview

- [ARCHITECTURE.md](ARCHITECTURE.md): 現行アーキテクチャの正本
- [kernel_development_guidelines.md](kernel_development_guidelines.md): 実装時の開発規約
- [kernel_boot_sequence.md](kernel_boot_sequence.md): ブート経路と runtime handoff
- [LINKER_GUIDELINES.md](LINKER_GUIDELINES.md): リンカ設定と CI 安全策

## 推奨参照順（最短ルート）

1. [ARCHITECTURE.md](ARCHITECTURE.md)（正本）
2. [decisions/README.md](decisions/README.md)（採択済み判断）
3. [kernel_development_guidelines.md](kernel_development_guidelines.md)（実装規約）
4. [capabilities.md](capabilities.md)（権限モデル）
5. [reference/api-reference.md](reference/api-reference.md)（API 形状）
6. [exorust_design/README.md](exorust_design/README.md)（参考実装）
7. [archive/README.md](archive/README.md)（履歴資料）

補足:

- `archive/` は履歴参照用であり、現行仕様の正本ではありません。
- 仕様の競合時は `ARCHITECTURE.md` と Accepted ADR を優先してください。

## Design

- [design-hub.md](design-hub.md): Variant A / B / C の比較と推奨案
- [capabilities.md](capabilities.md): Capability モデルと API
- [kernel_driver_boundary.md](kernel_driver_boundary.md): カーネル / ドライバ責務境界
- [driver_dependency.md](driver_dependency.md): ドライバ依存ルール
- [design_variants/variant-a-capability-first.md](design_variants/variant-a-capability-first.md): canonical baseline
- [design_variants/variant-b-hybrid-hardware-accelerated.md](design_variants/variant-b-hybrid-hardware-accelerated.md): 追加防御を伴う研究案
- [design_variants/variant-c-pks-mandatory.md](design_variants/variant-c-pks-mandatory.md): 高保証 SKU 向け研究案
- [exorust_design/README.md](exorust_design/README.md): 設計サンプルコードの位置付け

## Decisions

- [decisions/README.md](decisions/README.md): Architecture Decision Record（ADR）索引
- [decisions/ADR-0007-variant-a-as-canonical-baseline.md](decisions/ADR-0007-variant-a-as-canonical-baseline.md): 既定案（Variant A）採択記録
- [decisions/archive/README.md](decisions/archive/README.md): superseded / archived ADR 履歴

## Reference

- [reference/api-reference.md](reference/api-reference.md): 公開 API と設計意図
- [reference/deprecations.md](reference/deprecations.md): 廃止済み API と移行ガイド
- [reference/lru-block-cache.md](reference/lru-block-cache.md): LRU ブロックキャッシュ実装リファレンス

## Runbooks

- [runbooks/driver-cell-qemu.md](runbooks/driver-cell-qemu.md): DriverCell / LiveUpdate の手動 QEMU 検証

## Proposals

- [proposals/exoshell-improvements.md](proposals/exoshell-improvements.md): ExoShell 改善提案

## Component Docs

- [../bootloader/FUTURE_ROADMAP.md](../bootloader/FUTURE_ROADMAP.md): ExoLoader のロードマップ
- [../drivers/README.md](../drivers/README.md): ドライバディレクトリ案内
- [../drivers/nvme/README.md](../drivers/nvme/README.md): NVMe ドライバ案内
- [../libs/sync/README.md](../libs/sync/README.md): `libs/sync` の設計意図
- [../tools/e2e_zero_copy/README.md](../tools/e2e_zero_copy/README.md): E2E zero-copy storage test
- [../tools/framebuffer_bench/README.md](../tools/framebuffer_bench/README.md): framebuffer bench 案内
- [../tools/framebuffer_bench/BENCH_BASELINE.md](../tools/framebuffer_bench/BENCH_BASELINE.md): framebuffer bench baseline
- [../tools/iommu_bench/README.md](../tools/iommu_bench/README.md): IOMMU bench 案内

## Archive

- [archive/README.md](archive/README.md): 履歴資料の読み方

## 関連文書

- [../README.md](../README.md)
- [design-hub.md](design-hub.md)
- [archive/README.md](archive/README.md)
