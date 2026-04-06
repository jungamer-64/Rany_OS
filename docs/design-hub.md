# ExoRust 設計ハブ

- Status: Canonical design comparison hub
- Audience: 設計方針を確認する contributor、レビュー担当者、研究案との差分を知りたい実装者
- Related: [ドキュメントハブ](README.md), [アーキテクチャ概要](ARCHITECTURE.md), [Variant A](design_variants/variant-a-capability-first.md)

この文書は、ExoRust の設計方針を比較するためのハブです。実装既定案と研究案を分離し、何を正本として扱うかを明確にします。

## 文書構成

- [Variant A: Capability-First Baseline](design_variants/variant-a-capability-first.md)
- [Variant B: Hybrid Hardware-Assisted Isolation](design_variants/variant-b-hybrid-hardware-accelerated.md)
- [Variant C: PKS-Mandatory High-Assurance SKU](design_variants/variant-c-pks-mandatory.md)
- [運用向けアーキテクチャ概要](ARCHITECTURE.md)
- [開発ガイドライン](kernel_development_guidelines.md)
- [Capability 設計](capabilities.md)
- [設計サンプルコードの位置付け](exorust_design/README.md)

## 共通原則

- Safe Rust を優先し、`unsafe` は Framework 層に集約する。
- ドメイン間データは Exchange Heap と `RRef` で移動し、共有メモリ前提の設計を避ける。
- DMA は IOMMU を必須前提とし、Framework API 経由でのみ扱う。
- cross-domain API、`cell.swap`、`mmio.write`、DMA / IOMMU 制御、他ドメイン観測は Capability を必須にする。
- ドメイン境界 ABI は `#[repr(C)]` 型、opaque handle、token、明示的なシリアライズ形式に限定する。
- ISR では `wake()` を直接呼ばず、deferred wake で通常コンテキストへ橋渡しする。
- 通常の障害通知は `Result` ベースとし、panic は最終封じ込め手段として扱う。

## 推奨案

既定案は [Variant A](design_variants/variant-a-capability-first.md) です。

- Capability、署名検証、IOMMU、Framework 境界を authority の根として定義しやすい。
- 未対応 CPU でも安全モデルを崩さずに成立する。
- 実装・レビュー・文書間の整合を最も取りやすい。

## Variant B / C の位置付け

- Variant B は、対応 CPU で PKS / MPK 系を追加防御として使う研究・将来拡張案です。
- Variant C は、Supervisor 向け保護キー相当を必須とする高保証 SKU 向け研究案です。
- `docs/exorust_design/security/` の擬似コードは主に Variant B / C の参考実装として扱います。

## 関連文書

- [README.md](../README.md)
- [README.md](README.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
