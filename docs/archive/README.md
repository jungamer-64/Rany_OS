# Archive Index

- Status: Historical archive index
- Audience: 過去の検討記録、監査履歴、完了済み移行メモを参照したい contributor
- Related: [ドキュメントハブ](../README.md), [設計ハブ](../design-hub.md)

このディレクトリは履歴資料の保管場所です。ここにある文書は現行仕様の正本ではなく、過去の検討、監査、移行計画、完了メモを残すためのものです。

## 読み方

- 現行仕様や現在の推奨実装を確認したい場合は、まず [../README.md](../README.md)、[../ARCHITECTURE.md](../ARCHITECTURE.md)、[../decisions/README.md](../decisions/README.md) を参照してください。
- archive 文書内のコードパスやモジュール名は、執筆当時の構成を記録したものです。現行 tree と一致しない場合があります。
- 旧計画書は「なぜその判断に至ったか」を追うための資料として読み、現行の正規ルール（Canonical 文書 + Accepted ADR）とは切り分けて扱ってください。

## 旧設計案から現行正本への対応

`Rustカーネル設計案.md` を参照する場合は、以下の現行正本へ読み替えてください。

| 旧設計案の主題 | 現行の参照先 |
| --- | --- |
| SAS / SPL / Async-First の原則 | [../ARCHITECTURE.md](../ARCHITECTURE.md), [../decisions/ADR-0001-sas-spl-foundation.md](../decisions/ADR-0001-sas-spl-foundation.md), [../decisions/ADR-0002-async-first-execution-model.md](../decisions/ADR-0002-async-first-execution-model.md) |
| Capability-first authority | [../ARCHITECTURE.md](../ARCHITECTURE.md), [../capabilities.md](../capabilities.md), [../decisions/ADR-0003-capability-first-authority-model.md](../decisions/ADR-0003-capability-first-authority-model.md) |
| Exchange Heap / `RRef` | [../ARCHITECTURE.md](../ARCHITECTURE.md), [../decisions/ADR-0005-exchange-heap-rref-domain-transfer.md](../decisions/ADR-0005-exchange-heap-rref-domain-transfer.md) |
| DMA / IOMMU 必須 | [../ARCHITECTURE.md](../ARCHITECTURE.md), [../decisions/ADR-0006-iommu-mandatory-for-dma.md](../decisions/ADR-0006-iommu-mandatory-for-dma.md) |
| Durability / persistence（WAL / PMEM / CoW / DAX） | [../ARCHITECTURE.md](../ARCHITECTURE.md), [../reference/durability.md](../reference/durability.md), [../decisions/ADR-0008-durability-baseline-expands-to-cow-and-dax.md](../decisions/ADR-0008-durability-baseline-expands-to-cow-and-dax.md) |
| Runtime QoS / resource accounting | [../ARCHITECTURE.md](../ARCHITECTURE.md), [../reference/runtime-qos.md](../reference/runtime-qos.md), [../kernel_development_guidelines.md](../kernel_development_guidelines.md) |
| Resilience / recovery（checkpoint / restart / replication） | [../ARCHITECTURE.md](../ARCHITECTURE.md), [../reference/resilience-recovery.md](../reference/resilience-recovery.md), [../decisions/ADR-0010-runtime-resilience-baseline.md](../decisions/ADR-0010-runtime-resilience-baseline.md) |
| Live Update 実運用観点 | [../ARCHITECTURE.md](../ARCHITECTURE.md), [../reference/resilience-recovery.md](../reference/resilience-recovery.md), [../runbooks/driver-cell-qemu.md](../runbooks/driver-cell-qemu.md) |
| NUMA / power / fault hardening | [../ARCHITECTURE.md](../ARCHITECTURE.md), [../kernel_development_guidelines.md](../kernel_development_guidelines.md), [../decisions/ADR-0011-locality-power-and-fault-hardening-baseline.md](../decisions/ADR-0011-locality-power-and-fault-hardening-baseline.md) |
| 実装規約（unsafe 境界、ISR、panic 封じ込め、tracing） | [../kernel_development_guidelines.md](../kernel_development_guidelines.md), [../reference/observability-debug.md](../reference/observability-debug.md) |
| Secure Boot / loader chain | [../ARCHITECTURE.md](../ARCHITECTURE.md), [../../bootloader/FUTURE_ROADMAP.md](../../bootloader/FUTURE_ROADMAP.md) |
| デバッグ / 可観測性 / tracing | [../kernel_development_guidelines.md](../kernel_development_guidelines.md), [../reference/observability-debug.md](../reference/observability-debug.md), [../decisions/ADR-0009-observability-baseline-includes-tracing-and-reproducibility.md](../decisions/ADR-0009-observability-baseline-includes-tracing-and-reproducibility.md) |
| ベンチマーク目標 / 成功基準 | [../reference/performance-targets.md](../reference/performance-targets.md) |
| 参考実装コード | [../exorust_design/README.md](../exorust_design/README.md) |
| 研究案（HW支援強化） | [../design_variants/variant-b-hybrid-hardware-accelerated.md](../design_variants/variant-b-hybrid-hardware-accelerated.md), [../design_variants/variant-c-pks-mandatory.md](../design_variants/variant-c-pks-mandatory.md) |

補足:

- Secure Boot の canonical requirement は `docs/` 側で要約し、UEFI / Shim / MOK / db / dbx の詳細は
  [../../bootloader/FUTURE_ROADMAP.md](../../bootloader/FUTURE_ROADMAP.md)
  を component detail として参照してください。
- 旧設計案の benchmark / resilience / tracing のうち採択済み項目は、
  `Canonical requirement` または `Canonical target / implementation pending`
  として現行 docs に再配置されています。

## 収録文書

- [ASYNC_SWAPOUT.md](ASYNC_SWAPOUT.md)
- [DESIGN_COMPLIANCE_AUDIT_20260302.md](DESIGN_COMPLIANCE_AUDIT_20260302.md)
- [E0152_INVESTIGATION.md](E0152_INVESTIGATION.md)
- [ECDH_IMPLEMENTATION_PLAN.md](ECDH_IMPLEMENTATION_PLAN.md)
- [IOMMU_INTEGRATION_PLAN.md](IOMMU_INTEGRATION_PLAN.md)
- [IOVA_ALLOCATOR_OPTIMIZATIONS.md](IOVA_ALLOCATOR_OPTIMIZATIONS.md)
- [LOCK_MIGRATION_PLAN.md](LOCK_MIGRATION_PLAN.md)
- [MM_MODULE_ANALYSIS.md](MM_MODULE_ANALYSIS.md)
- [NETWORK_REORG_PLAN.md](NETWORK_REORG_PLAN.md)
- [buddy_allocator_comparison.md](buddy_allocator_comparison.md)
- [fat32_page_backed_buffers_plan.md](fat32_page_backed_buffers_plan.md)
- [migration_from_posix.md](migration_from_posix.md)
- [network-compliance-fix-plan.md](network-compliance-fix-plan.md)
- [Rustカーネル設計案.md](Rustカーネル設計案.md)

## 関連文書

- [../README.md](../README.md)
- [../design-hub.md](../design-hub.md)
- [../decisions/README.md](../decisions/README.md)
