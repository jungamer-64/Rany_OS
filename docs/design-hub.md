# ExoRust 設計ハブ

- Status: Canonical design comparison hub
- Audience: 設計方針を確認する contributor、レビュー担当者、研究案との差分を知りたい実装者
- Related: [ドキュメントハブ](README.md), [アーキテクチャ概要](ARCHITECTURE.md), [Variant A](design_variants/variant-a-capability-first.md)

この文書は、ExoRust の設計方針を比較するためのハブです。実装既定案と研究案を分離し、何を正本として扱うかを明確にします。

## 文書構成

- [Variant A: Capability-First Baseline](design_variants/variant-a-capability-first.md)
- [Variant B: Hybrid Hardware-Assisted Isolation](design_variants/variant-b-hybrid-hardware-accelerated.md)
- [Variant C: PKS-Mandatory High-Assurance SKU](design_variants/variant-c-pks-mandatory.md)
- [Hardware-Assisted Security Notes](design_variants/hardware-assisted-security-notes.md)
- [運用向けアーキテクチャ概要](ARCHITECTURE.md)
- [開発ガイドライン](kernel_development_guidelines.md)
- [Capability 設計](capabilities.md)
- [Execution Fairness Reference](reference/execution-fairness.md)
- [Resilience / Recovery Reference](reference/resilience-recovery.md)
- [Performance Targets Reference](reference/performance-targets.md)
- [Kernel Roadmap Proposal](proposals/kernel-roadmap.md)
- [Archive Migration Checklist](reference/archive-migration-checklist.md)
- [設計サンプルコードの位置付け](exorust_design/README.md)

## 推奨参照順

設計判断を行うときは、次の順で読む。

1. [ARCHITECTURE.md](ARCHITECTURE.md)（正本）
2. [decisions/README.md](decisions/README.md)（採択理由と境界条件）
3. [Variant A](design_variants/variant-a-capability-first.md)（canonical baseline）
4. [kernel_development_guidelines.md](kernel_development_guidelines.md)（実装規約）
5. [capabilities.md](capabilities.md)（権限設計）

Variant B/C や `docs/exorust_design/` は、正本を補う研究・参考資料として扱う。

## 共通原則

- Safe Rust を優先し、`unsafe` は Framework 層に集約する。
- ドメイン間データは Exchange Heap と `RRef` で移動し、共有メモリ前提の設計を避ける。
- DMA は IOMMU を必須前提とし、Framework API 経由でのみ扱う。
- cross-domain API、`cell.swap`、`mmio.write`、DMA / IOMMU 制御、他ドメイン観測は Capability を必須にする。
- ドメイン境界 ABI は `#[repr(C)]` 型、opaque handle、token、明示的なシリアライズ形式に限定する。
- ISR では `wake()` を直接呼ばず、deferred wake で通常コンテキストへ橋渡しする。
- 通常の障害通知は `Result` ベースとし、panic は最終封じ込め手段として扱う。
- 採択済みだが段階実装中の項目は `Canonical target / implementation pending` と明記し、保留中の論点と混同しない。

## 意思決定記録（ADR）

設計判断の採択理由・代替案・影響範囲は [ADR Index](decisions/README.md) で追跡します。

- [ADR-0001: SAS/SPL Foundation](decisions/ADR-0001-sas-spl-foundation.md)
- [ADR-0002: Async-First Execution Model](decisions/ADR-0002-async-first-execution-model.md)
- [ADR-0003: Capability-First Authority Model](decisions/ADR-0003-capability-first-authority-model.md)
- [ADR-0004: Unsafe Confined to Framework Boundary](decisions/ADR-0004-unsafe-confined-to-framework-boundary.md)
- [ADR-0005: Exchange Heap + RRef Domain Transfer](decisions/ADR-0005-exchange-heap-rref-domain-transfer.md)
- [ADR-0006: IOMMU Mandatory for DMA](decisions/ADR-0006-iommu-mandatory-for-dma.md)
- [ADR-0007: Variant A as Canonical Baseline](decisions/ADR-0007-variant-a-as-canonical-baseline.md)
- [ADR-0008: Durability Baseline Expands to CoW + DAX](decisions/ADR-0008-durability-baseline-expands-to-cow-and-dax.md)
- [ADR-0009: Observability Baseline Includes Tracing + Reproducibility](decisions/ADR-0009-observability-baseline-includes-tracing-and-reproducibility.md)
- [ADR-0010: Runtime Resilience Baseline](decisions/ADR-0010-runtime-resilience-baseline.md)
- [ADR-0011: Locality / Power / Fault Hardening Baseline](decisions/ADR-0011-locality-power-and-fault-hardening-baseline.md)

## 推奨案

既定案は [Variant A](design_variants/variant-a-capability-first.md) です。

- Capability、署名検証、IOMMU、Framework 境界を authority の根として定義しやすい。
- 未対応 CPU でも安全モデルを崩さずに成立する。
- 実装・レビュー・文書間の整合を最も取りやすい。

## Variant B / C の位置付け

- Variant B は、対応 CPU で PKS / MPK 系を追加防御として使う研究・将来拡張案です。
- Variant C は、Supervisor 向け保護キー相当を必須とする高保証 SKU 向け研究案です。
- `docs/exorust_design/security/` の擬似コードは主に Variant B / C の参考実装として扱います。

## 旧設計案の残存細部の移行先

- 旧 4.4 の starvation / fairness 詳細は [reference/execution-fairness.md](reference/execution-fairness.md) に集約する。
- 旧 9.2 の Spectre / MPK / LFENCE / cache partitioning 詳細は [design_variants/hardware-assisted-security-notes.md](design_variants/hardware-assisted-security-notes.md) に移す。
- 旧 11 / 13 のロードマップと将来課題は [proposals/kernel-roadmap.md](proposals/kernel-roadmap.md) に現代化して移す。
- 対応表全体は [reference/archive-migration-checklist.md](reference/archive-migration-checklist.md) を正とする。

## 関連文書

- [README.md](../README.md)
- [README.md](README.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
