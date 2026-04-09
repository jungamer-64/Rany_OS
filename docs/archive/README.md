# ExoRust 履歴資料アーカイブ

- Status: Historical archive index
- Audience: 過去の検討記録、監査履歴、完了済み移行メモを参照したい contributor
- Related: [ドキュメントハブ](../README.md), [アーキテクチャ概要](../architecture.md), [ADR Index](../decisions/README.md)

このディレクトリは履歴資料の保管場所です。ここにある文書は現行仕様の正本ではなく、過去の検討、監査、移行計画、完了メモを残すためのものです。

すべての archive 文書は先頭に `Archive note` バナーを置き、まず canonical docs とこの索引へ戻れるようにします。

## 読み方

- 現行仕様や現在の推奨実装を確認したい場合は、まず [../README.md](../README.md)、[../architecture.md](../architecture.md)、[../decisions/README.md](../decisions/README.md) を参照してください。
- archive 文書内のコードパスやモジュール名は、執筆当時の構成を記録したものです。現行 tree と一致しない場合があります。
- 旧計画書は「なぜその判断に至ったか」を追うための資料として読み、現行の正規ルール（Canonical 文書 + Accepted ADR）とは切り分けて扱ってください。

## 旧設計案から現行正本への対応

[rust-kernel-design-proposal.md](rust-kernel-design-proposal.md) を参照する場合は、以下の現行正本へ読み替えてください。

| 旧設計案の主題 | 現行の参照先 |
| --- | --- |
| SAS / SPL / Async-First の原則 | [../architecture.md](../architecture.md), [../decisions/adr-0001-sas-spl-foundation.md](../decisions/adr-0001-sas-spl-foundation.md), [../decisions/adr-0002-async-first-execution-model.md](../decisions/adr-0002-async-first-execution-model.md) |
| Capability-first authority | [../architecture.md](../architecture.md), [../capabilities.md](../capabilities.md), [../decisions/adr-0003-capability-first-authority-model.md](../decisions/adr-0003-capability-first-authority-model.md) |
| Exchange Heap / `RRef` | [../architecture.md](../architecture.md), [../decisions/adr-0005-exchange-heap-rref-domain-transfer.md](../decisions/adr-0005-exchange-heap-rref-domain-transfer.md) |
| DMA / IOMMU 必須 | [../architecture.md](../architecture.md), [../decisions/adr-0006-iommu-mandatory-for-dma.md](../decisions/adr-0006-iommu-mandatory-for-dma.md) |
| Durability / persistence（WAL / PMEM / CoW / DAX） | [../architecture.md](../architecture.md), [../reference/durability.md](../reference/durability.md), [../decisions/adr-0008-durability-baseline-expands-to-cow-and-dax.md](../decisions/adr-0008-durability-baseline-expands-to-cow-and-dax.md) |
| Runtime QoS / resource accounting | [../architecture.md](../architecture.md), [../reference/runtime-qos.md](../reference/runtime-qos.md), [../kernel-development-guidelines.md](../kernel-development-guidelines.md) |
| Resilience / recovery（checkpoint / restart / replication） | [../architecture.md](../architecture.md), [../reference/resilience-recovery.md](../reference/resilience-recovery.md), [../decisions/adr-0010-runtime-resilience-baseline.md](../decisions/adr-0010-runtime-resilience-baseline.md) |
| Live Update 実運用観点 | [../architecture.md](../architecture.md), [../reference/resilience-recovery.md](../reference/resilience-recovery.md), [../runbooks/driver-cell-qemu.md](../runbooks/driver-cell-qemu.md) |
| NUMA / power / fault hardening | [../architecture.md](../architecture.md), [../kernel-development-guidelines.md](../kernel-development-guidelines.md), [../decisions/adr-0011-locality-power-and-fault-hardening-baseline.md](../decisions/adr-0011-locality-power-and-fault-hardening-baseline.md) |
| 実装規約（unsafe 境界、ISR、panic 封じ込め、tracing） | [../kernel-development-guidelines.md](../kernel-development-guidelines.md), [../reference/observability-debug.md](../reference/observability-debug.md) |
| Secure Boot / loader chain | [../architecture.md](../architecture.md), [../../bootloader/future-roadmap.md](../../bootloader/future-roadmap.md) |
| デバッグ / 可観測性 / tracing | [../kernel-development-guidelines.md](../kernel-development-guidelines.md), [../reference/observability-debug.md](../reference/observability-debug.md), [../decisions/adr-0009-observability-baseline-includes-tracing-and-reproducibility.md](../decisions/adr-0009-observability-baseline-includes-tracing-and-reproducibility.md) |
| ベンチマーク目標 / 成功基準 | [../reference/performance-targets.md](../reference/performance-targets.md) |
| 参考実装コード | [../design-samples/README.md](../design-samples/README.md) |
| 研究案（HW支援強化） | [../design_variants/variant-b-hybrid-hardware-accelerated.md](../design_variants/variant-b-hybrid-hardware-accelerated.md), [../design_variants/variant-c-pks-mandatory.md](../design_variants/variant-c-pks-mandatory.md) |

補足:

- Secure Boot の canonical requirement は `docs/` 側で要約し、UEFI / Shim / MOK / db / dbx の詳細は
  [../../bootloader/future-roadmap.md](../../bootloader/future-roadmap.md)
  を component detail として参照してください。
- 旧設計案の benchmark / resilience / tracing のうち採択済み項目は、
  `Canonical requirement` または `Canonical target / implementation pending`
  として現行 docs に再配置されています。

## 収録文書

- [async-swapout.md](async-swapout.md)
- [design-compliance-audit-20260302.md](design-compliance-audit-20260302.md)
- [e0152-investigation.md](e0152-investigation.md)
- [ecdh-implementation-plan.md](ecdh-implementation-plan.md)
- [iommu-integration-plan.md](iommu-integration-plan.md)
- [iova-allocator-optimizations.md](iova-allocator-optimizations.md)
- [lock-migration-plan.md](lock-migration-plan.md)
- [mm-module-analysis.md](mm-module-analysis.md)
- [network-reorg-plan.md](network-reorg-plan.md)
- [buddy-allocator-comparison.md](buddy-allocator-comparison.md)
- [fat32-page-backed-buffers-plan.md](fat32-page-backed-buffers-plan.md)
- [migration-from-posix.md](migration-from-posix.md)
- [network-compliance-fix-plan.md](network-compliance-fix-plan.md)
- [rust-kernel-design-proposal.md](rust-kernel-design-proposal.md)

## 関連文書

- [../README.md](../README.md)
- [../design-overview.md](../design-overview.md)
- [../decisions/README.md](../decisions/README.md)
