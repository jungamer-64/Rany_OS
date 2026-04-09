# ExoRust ドキュメントハブ

- Status: Canonical document index
- Audience: 設計確認、実装、レビュー、検証のために文書を辿る contributor
- Related: [README.md](../README.md), [アーキテクチャ概要](architecture.md), [履歴資料アーカイブ](archive/README.md)

このファイルは ExoRust 公開文書の唯一の総合入口です。canonical 文書、採択済み判断、reference、運用手順、履歴資料、component detail をここから辿れるように整理します。

## 最短ルート

1. [architecture.md](architecture.md): 現行アーキテクチャの正本
2. [decisions/README.md](decisions/README.md): 採択済みの設計判断と境界条件
3. [kernel-development-guidelines.md](kernel-development-guidelines.md): 実装規約
4. [reference/api-reference.md](reference/api-reference.md): 公開 API と設計意図
5. [design-overview.md](design-overview.md): Variant 比較と補助的な設計整理
6. [archive/README.md](archive/README.md): 履歴資料の入口

## 規範ラベル

- `Canonical requirement`: 現行 baseline で必須の要件
- `Canonical target`: 採択済みだが段階実装中の目標。未実装部分は `implementation pending` と明記する
- `Reference`: 実装整理、補助設計、公開面の読み替え
- `Design comparison`: canonical を補う比較・研究整理
- `Design sample`: コンパイル対象ではない擬似コード資料
- `Component detail`: 下位コンポーネントの詳細実装
- `Historical archive`: 履歴資料。現行正本ではない

補足:

- 仕様の競合時は `architecture.md` と Accepted ADR を優先してください。
- `design-overview.md` と `design-samples/` は canonical の補助資料であり、正本そのものではありません。
- `archive/` は履歴参照用です。設計判断の現行基準としては扱いません。

## Canonical

- [architecture.md](architecture.md): 現行アーキテクチャの正本
- [kernel-development-guidelines.md](kernel-development-guidelines.md): 実装規約
- [kernel-boot-sequence.md](kernel-boot-sequence.md): ブート経路と runtime handoff
- [linker-guidelines.md](linker-guidelines.md): リンカ設定と CI 安全策
- [capabilities.md](capabilities.md): Capability モデルと API
- [kernel-driver-boundary.md](kernel-driver-boundary.md): カーネル / ドライバ責務境界
- [driver-dependency.md](driver-dependency.md): ドライバ依存ルール

## Decisions

- [decisions/README.md](decisions/README.md): Architecture Decision Record（ADR）索引
- [decisions/adr-0007-variant-a-as-canonical-baseline.md](decisions/adr-0007-variant-a-as-canonical-baseline.md): 既定案（Variant A）採択記録
- [decisions/adr-0008-durability-baseline-expands-to-cow-and-dax.md](decisions/adr-0008-durability-baseline-expands-to-cow-and-dax.md): durability baseline 拡張
- [decisions/adr-0009-observability-baseline-includes-tracing-and-reproducibility.md](decisions/adr-0009-observability-baseline-includes-tracing-and-reproducibility.md): observability baseline 拡張
- [decisions/adr-0010-runtime-resilience-baseline.md](decisions/adr-0010-runtime-resilience-baseline.md): runtime resilience baseline
- [decisions/adr-0011-locality-power-and-fault-hardening-baseline.md](decisions/adr-0011-locality-power-and-fault-hardening-baseline.md): NUMA / power / fault hardening baseline
- [decisions/archive/README.md](decisions/archive/README.md): superseded / archived ADR 履歴

## Reference

- [reference/api-reference.md](reference/api-reference.md): 公開 API と設計意図
- [reference/durability.md](reference/durability.md): durability / persistence の現行整理
- [reference/execution-fairness.md](reference/execution-fairness.md): fuel / loop-bound / APIC fairness の現行整理
- [reference/runtime-qos.md](reference/runtime-qos.md): runtime QoS / resource accounting の現行整理
- [reference/resilience-recovery.md](reference/resilience-recovery.md): checkpoint / restart / replication / panic hardening の現行整理
- [reference/observability-debug.md](reference/observability-debug.md): observability / debug の現行整理
- [reference/performance-targets.md](reference/performance-targets.md): ベンチマーク目標と測定基準
- [reference/archive-migration-checklist.md](reference/archive-migration-checklist.md): archive 由来の残存細部の移行対応表
- [reference/deprecations.md](reference/deprecations.md): 廃止済み API と移行ガイド
- [reference/lru-block-cache.md](reference/lru-block-cache.md): LRU ブロックキャッシュ実装リファレンス

## Design Comparison

- [design-overview.md](design-overview.md): Variant A / B / C の比較と推奨案
- [design_variants/variant-a-capability-first.md](design_variants/variant-a-capability-first.md): canonical baseline の詳細
- [design_variants/variant-b-hybrid-hardware-accelerated.md](design_variants/variant-b-hybrid-hardware-accelerated.md): 追加防御を伴う研究案
- [design_variants/variant-c-pks-mandatory.md](design_variants/variant-c-pks-mandatory.md): 高保証 SKU 向け研究案
- [design_variants/hardware-assisted-security-notes.md](design_variants/hardware-assisted-security-notes.md): ハードウェア支援セキュリティ詳細の研究ノート

## Design Samples

- [design-samples/README.md](design-samples/README.md): 擬似コード資料の位置付け
- `design-samples/` 配下の `.rs` は設計意図を示すサンプルであり、ビルド対象ではありません。

archive 由来の残存細部の着地点:

- 旧 4.4: [reference/execution-fairness.md](reference/execution-fairness.md)
- 旧 9.2: [design_variants/hardware-assisted-security-notes.md](design_variants/hardware-assisted-security-notes.md)
- 旧 11 / 13: [proposals/kernel-roadmap.md](proposals/kernel-roadmap.md)
- 完全対応表: [reference/archive-migration-checklist.md](reference/archive-migration-checklist.md)

## Runbooks

- [runbooks/driver-cell-qemu.md](runbooks/driver-cell-qemu.md): DriverCell / LiveUpdate の手動 QEMU 検証

## Proposals

- [proposals/exoshell-improvements.md](proposals/exoshell-improvements.md): ExoShell 改善提案
- [proposals/kernel-roadmap.md](proposals/kernel-roadmap.md): 旧設計案 11 / 13 を workstream 化したロードマップ案

## Component Docs

- [../bootloader/future-roadmap.md](../bootloader/future-roadmap.md): ExoLoader のロードマップ、UEFI / Secure Boot / measured boot detail
- [../drivers/README.md](../drivers/README.md): ドライバディレクトリ案内
- [../drivers/nvme/README.md](../drivers/nvme/README.md): NVMe ドライバ案内
- [../libs/sync/README.md](../libs/sync/README.md): `libs/sync` の設計意図
- [../tools/e2e_zero_copy/README.md](../tools/e2e_zero_copy/README.md): E2E zero-copy storage test
- [../tools/framebuffer_bench/README.md](../tools/framebuffer_bench/README.md): framebuffer bench 案内
- [../tools/framebuffer_bench/bench-baseline.md](../tools/framebuffer_bench/bench-baseline.md): framebuffer bench baseline
- [../tools/iommu_bench/README.md](../tools/iommu_bench/README.md): IOMMU bench 案内

## Archive

- [archive/README.md](archive/README.md): 履歴資料の読み方
- [archive/rust-kernel-design-proposal.md](archive/rust-kernel-design-proposal.md): 旧設計案の長文アーカイブ

## 関連文書

- [../README.md](../README.md)
- [design-overview.md](design-overview.md)
- [archive/README.md](archive/README.md)
