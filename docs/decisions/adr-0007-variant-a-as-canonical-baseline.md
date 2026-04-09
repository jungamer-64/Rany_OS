# ADR-0007: Variant A as Canonical Baseline

- Status: Accepted
- Audience: 設計判断を行う contributor、運用設計者、レビュー担当者
- Related: [設計比較ガイド](../design-overview.md), [Variant A](../design_variants/variant-a-capability-first.md), [architecture.md](../architecture.md)
- Supersedes: None
- Superseded-By: None
- Date: 2026-04-07

## Context

ExoRust には Variant A/B/C の比較案がある。
実装・レビュー・運用で一貫した基準を持つためには、どれを canonical baseline とするかを明示する必要がある。

- Variant A: Capability-first を中心にした既定案
- Variant B: HW支援（PKS/MPK等）を追加防御として活用する研究案
- Variant C: 高保証SKU向けに保護機構必須化を強めた研究案

## Decision

設計基準として、Variant A を canonical baseline に採択する。

1. 現行の正本仕様は Variant A を前提に定義する。
2. Variant B/C は研究・将来拡張として扱う（正本基準にはしない）。
3. ハードウェア支援機構は optional defense として位置付ける。
4. 実装判断・レビュー判断・CI判断は Variant A 適合性を優先する。

## Consequences

- 実装/レビューの判断軸が一本化され、意思決定コストが下がる。
- 未対応CPU環境でも安全モデルを維持した実装方針を取れる。
- Variant B/C の実験実装は可能だが、正本への昇格には新ADRが必要になる。
- docsの重複説明を減らし、`design-hub` と ADR の二層で追跡しやすくなる。

## Alternatives Considered

1. **Variant Bを正本にする案**
   - 不採用理由: HW依存が強く、適用可能環境が限定される。
2. **Variant Cを正本にする案**
   - 不採用理由: 高保証SKU寄りで、一般運用基準としては過剰制約。
3. **正本を固定せず並立する案**
   - 不採用理由: 実装・レビュー・CI基準が分散し、運用コストが増える。

## Notes

- Variant の再採択や昇格判断は、必ず新しい ADR で記録する。

## References

- [../design-overview.md](../design-overview.md)
- [../design_variants/variant-a-capability-first.md](../design_variants/variant-a-capability-first.md)
