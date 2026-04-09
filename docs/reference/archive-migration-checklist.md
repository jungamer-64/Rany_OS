# Archive Design Migration Checklist

- Status: Reference
- Audience: 旧設計案から新 docs への対応関係を確認したい reviewer、移行漏れを棚卸ししたい contributor
- Related: [../design-overview.md](../design-overview.md), [execution-fairness.md](execution-fairness.md), [../design_variants/hardware-assisted-security-notes.md](../design_variants/hardware-assisted-security-notes.md), [../proposals/kernel-roadmap.md](../proposals/kernel-roadmap.md)

この checklist は、旧設計案の未移行クラスタ 4.4 / 9.2 / 11 / 13 が、non-archive docs のどこへ再配置されたかを追跡します。

## Checklist

| 旧設計案 | 主要論点 | 移行先 | 状態 |
| --- | --- | --- | --- |
| 4.4.1 | Fuel-based Execution | [execution-fairness.md](execution-fairness.md) | Moved |
| 4.4.1 | fuel quota / fuel consumption points | [execution-fairness.md](execution-fairness.md) | Moved |
| 4.4.2 | loop-bound proof | [execution-fairness.md](execution-fairness.md) | Moved |
| 4.4.3 | FFI checkpoint / trust classification / `eBPF` 風 instrumentation | [execution-fairness.md](execution-fairness.md) | Moved |
| 4.4.4 | APIC timeslice final defense | [execution-fairness.md](execution-fairness.md) | Moved |
| 9.2.1 | SAS 下の Spectre threat model | [../design_variants/hardware-assisted-security-notes.md](../design_variants/hardware-assisted-security-notes.md) | Moved |
| 9.2.2.1 | MPK / PKU 第一級市民化、protection key class strategy | [../design_variants/hardware-assisted-security-notes.md](../design_variants/hardware-assisted-security-notes.md) | Moved |
| 9.2.2.2 | WRPKRU-LFENCE tradeoff | [../design_variants/hardware-assisted-security-notes.md](../design_variants/hardware-assisted-security-notes.md) | Moved |
| 9.2.2 | cache partitioning / secret placement | [../design_variants/hardware-assisted-security-notes.md](../design_variants/hardware-assisted-security-notes.md) | Moved |
| 9.2.3 | Retpoline / IBRS / STIBP / IBPB | [../design_variants/hardware-assisted-security-notes.md](../design_variants/hardware-assisted-security-notes.md) | Moved |
| 11 フェーズ 1 | ブートストラップと基本ランタイム | [../proposals/kernel-roadmap.md](../proposals/kernel-roadmap.md) | Moved |
| 11.1.1 | ブートストラップシーケンス詳細 | [../kernel-boot-sequence.md](../kernel-boot-sequence.md) + [../proposals/kernel-roadmap.md](../proposals/kernel-roadmap.md) | Moved |
| 11 フェーズ 2 | Async Executor と割り込み基盤 | [../proposals/kernel-roadmap.md](../proposals/kernel-roadmap.md) + [execution-fairness.md](execution-fairness.md) | Moved |
| 11 フェーズ 3 | セルローダーと分離機構 | [../proposals/kernel-roadmap.md](../proposals/kernel-roadmap.md) | Moved |
| 11 フェーズ 4a | VirtIO-net 基本実装 | [../proposals/kernel-roadmap.md](../proposals/kernel-roadmap.md) | Moved |
| 11 フェーズ 4b | ゼロコピー最適化 / mempool / scatter-gather | [../proposals/kernel-roadmap.md](../proposals/kernel-roadmap.md) + [api-reference.md](api-reference.md) | Moved |
| 11 フェーズ 4c | polling / batch processing | [../proposals/kernel-roadmap.md](../proposals/kernel-roadmap.md) + [api-reference.md](api-reference.md) | Moved |
| 11 フェーズ 4d | 実 NIC 対応 / SR-IOV / offload | [../proposals/kernel-roadmap.md](../proposals/kernel-roadmap.md) | Moved |
| 13.1 | threat model / formal assurance / unsafe audit | [../proposals/kernel-roadmap.md](../proposals/kernel-roadmap.md) | Moved |
| 13.2 | benchmark target / success criteria | [../reference/performance-targets.md](../reference/performance-targets.md) + [../proposals/kernel-roadmap.md](../proposals/kernel-roadmap.md) | Moved |
| 13.3.1 | replication | [../reference/resilience-recovery.md](../reference/resilience-recovery.md) + [../proposals/kernel-roadmap.md](../proposals/kernel-roadmap.md) | Moved |
| 13.3.2 | checkpoint / recovery | [../reference/resilience-recovery.md](../reference/resilience-recovery.md) + [../proposals/kernel-roadmap.md](../proposals/kernel-roadmap.md) | Moved |
| 13.3.3 | heartbeat / auto-restart / reroute | [../reference/resilience-recovery.md](../reference/resilience-recovery.md) + [../proposals/kernel-roadmap.md](../proposals/kernel-roadmap.md) | Moved |
| 13.4 | future topics | [../proposals/kernel-roadmap.md](../proposals/kernel-roadmap.md) | Moved |

## 関連文書

- [../design-overview.md](../design-overview.md)
- [execution-fairness.md](execution-fairness.md)
- [../design_variants/hardware-assisted-security-notes.md](../design_variants/hardware-assisted-security-notes.md)
- [../proposals/kernel-roadmap.md](../proposals/kernel-roadmap.md)
