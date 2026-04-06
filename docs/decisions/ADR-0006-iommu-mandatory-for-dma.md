# ADR-0006: IOMMU Mandatory for DMA

- Status: Accepted
- Audience: DMA/デバイスドライバ、メモリ保護、プラットフォーム統合を担当する contributor
- Related: [ARCHITECTURE.md](../ARCHITECTURE.md), [Variant A](../design_variants/variant-a-capability-first.md), [開発ガイドライン](../kernel_development_guidelines.md)
- Supersedes: None
- Superseded-By: None
- Date: 2026-04-07

## Context

DMA は CPU 権限チェックを迂回し得るため、IOMMU なしの任意物理アドレスDMAは重大リスクになる。
SPL/SAS 環境であっても DMA 境界をハードウェアで制限する必要がある。

## Decision

DMA 制御方針として以下を採択する。

1. DMA 運用は IOMMU 有効化を必須前提とする。
2. DMA バッファ確保は Framework API（例: `alloc_dma_buffer()`）経由のみ許可する。
3. 任意アドレスDMA、IOMMUバイパス、DMA中バッファへのCPU側アクセスを禁止する。
4. IOMMU が利用できない構成は通常運用対象外（制限モードまたは起動拒否）とする。

## Consequences

- DMA 由来の越境アクセスリスクを大幅に低減できる。
- ドライバ実装に対し API 遵守が必須になり、低レイヤ自由度は下がる。
- 対応ハードウェア条件が明確になり、運用要件が厳格化される。
- テスト/CIでIOMMU前提シナリオを維持する必要がある。

## Alternatives Considered

1. **IOMMUを推奨（任意）に留める案**
   - 不採用理由: 権限境界の一貫性が崩れ、環境差で安全性が変動する。
2. **ドライバごとに個別制御する案**
   - 不採用理由: 運用と監査が複雑化し、抜け漏れが発生しやすい。

## Notes

- 本ADRはセキュリティ前提のため、性能最適化より優先される。

## References

- [../ARCHITECTURE.md](../ARCHITECTURE.md)
- [../kernel_development_guidelines.md](../kernel_development_guidelines.md)
