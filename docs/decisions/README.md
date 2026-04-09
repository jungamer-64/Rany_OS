# ADR Index

- Status: Canonical decision index
- Audience: 設計判断の背景と採択履歴を追いたい contributor、レビュー担当者
- Related: [ドキュメントハブ](../README.md), [設計比較ガイド](../design-overview.md), [開発ガイドライン](../kernel-development-guidelines.md)

このディレクトリは ExoRust の Architecture Decision Record（ADR）正本です。
仕様本文（Architecture / Guidelines）と、採択理由・代替案・影響範囲（ADR）を分離して管理します。

## 運用ルール

### ADRを作成するトリガー

次のいずれかに該当する変更は ADR を必須とします。

- 破壊的変更（既存 API / ABI / 境界条件を変える）
- 複数案比較が必要な設計変更（Variant 選択、採択根拠が必要）
- セキュリティ境界や authority の根に関わる変更（Capability / IOMMU / 署名検証 / unsafe 境界）
- 運用基準を変える変更（canonical baseline、必須ハードウェア要件など）

### ステータス遷移

- Proposed: 提案中
- Accepted: 採択済み（現行正本の判断）
- Superseded: 後続 ADR に置き換え済み
- Deprecated: 廃止予定（移行期間中）
- Archived: 履歴保管

### 採番規則

- 連番方式を採用します（`ADR-0001` から開始）。
- 文書 ID は `ADR-000N` を使い、ファイル名は `adr-000N-<short-title>.md` 形式を使います。
- 同じ番号の再利用は禁止です。

### 言語方針

- 本文は日本語中心で記述します。
- 専門用語は英語を併記します（例: Single Address Space, deferred wake）。

### Superseded運用

- 新 ADR 側に `Supersedes` を記載します。
- 旧 ADR 側に `Superseded-By` を記載します。
- 廃止済み ADR は必要に応じて [archive/](archive/README.md) へ移動します。

## ADR一覧

| ID | Title | Status | Date |
| --- | --- | --- | --- |
| [ADR-0001](adr-0001-sas-spl-foundation.md) | SAS/SPL Foundation | Accepted | 2026-04-07 |
| [ADR-0002](adr-0002-async-first-execution-model.md) | Async-First Execution Model | Accepted | 2026-04-07 |
| [ADR-0003](adr-0003-capability-first-authority-model.md) | Capability-First Authority Model | Accepted | 2026-04-07 |
| [ADR-0004](adr-0004-unsafe-confined-to-framework-boundary.md) | Unsafe Confined to Framework Boundary | Accepted | 2026-04-07 |
| [ADR-0005](adr-0005-exchange-heap-rref-domain-transfer.md) | Exchange Heap + RRef Domain Transfer | Accepted | 2026-04-07 |
| [ADR-0006](adr-0006-iommu-mandatory-for-dma.md) | IOMMU Mandatory for DMA | Accepted | 2026-04-07 |
| [ADR-0007](adr-0007-variant-a-as-canonical-baseline.md) | Variant A as Canonical Baseline | Accepted | 2026-04-07 |
| [ADR-0008](adr-0008-durability-baseline-expands-to-cow-and-dax.md) | Durability Baseline Expands to CoW Snapshot + DAX | Accepted | 2026-04-09 |
| [ADR-0009](adr-0009-observability-baseline-includes-tracing-and-reproducibility.md) | Observability Baseline Includes Tracing + Reproducibility | Accepted | 2026-04-09 |
| [ADR-0010](adr-0010-runtime-resilience-baseline.md) | Runtime Resilience Baseline | Accepted | 2026-04-09 |
| [ADR-0011](adr-0011-locality-power-and-fault-hardening-baseline.md) | Locality / Power / Fault Hardening Baseline | Accepted | 2026-04-09 |

## 関連文書

- [../README.md](../README.md)
- [../design-overview.md](../design-overview.md)
- [../architecture.md](../architecture.md)
- [archive/README.md](archive/README.md)
