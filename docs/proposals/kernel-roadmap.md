# Kernel Roadmap

- Status: Proposal
- Audience: 実装順序、workstream の切り分け、archive 由来の今後の課題を整理したい contributor
- Related: [../kernel_boot_sequence.md](../kernel_boot_sequence.md), [../reference/performance-targets.md](../reference/performance-targets.md), [../reference/resilience-recovery.md](../reference/resilience-recovery.md), [../../bootloader/FUTURE_ROADMAP.md](../../bootloader/FUTURE_ROADMAP.md)

この文書は、旧設計案 11 / 13 のロードマップと将来課題を、月数ベースではなく workstream ベースへ現代化した proposal です。
canonical baseline や release commitment を定義する文書ではありません。

## 位置付け

- 現行の正本は [../ARCHITECTURE.md](../ARCHITECTURE.md) と Accepted ADR 群であり、本書はそれらを実装順序へ落とす proposal である。
- 旧設計案の「何ヶ月で達成するか」は再利用せず、workstream ごとの出口条件と依存関係で整理する。
- 既存の boot sequence、secure boot detail、performance targets、resilience reference は重複せず参照する。

## Workstreams

### 1. Boot / runtime bring-up

- 目的:
  loader handoff、early executor handoff、runtime finalization、SMP/TLS/runtime services まわりの bring-up を安定化する。
- 依存する正本:
  [../kernel_boot_sequence.md](../kernel_boot_sequence.md),
  [../../bootloader/FUTURE_ROADMAP.md](../../bootloader/FUTURE_ROADMAP.md)
- 代表テーマ:
  early memory / NUMA handoff、BSP/AP executor provision、runtime local timer 切替、late integration retry。

### 2. Network / datapath maturity

- 目的:
  zero-copy datapath、packet pool、batch processing、scatter-gather submission を整理し、測定可能な network path へ育てる。
- 依存する正本:
  [../reference/api-reference.md](../reference/api-reference.md),
  [../reference/performance-targets.md](../reference/performance-targets.md)
- 代表テーマ:
  RAW endpoint / datapath の語彙統一、ownership-based buffering、throughput / latency measurement、polling coexistence。

### 3. Real NIC enablement

- 目的:
  QEMU / VirtIO 中心の検証から、実 NIC の bring-up と offload の検証へ進む。
- 依存する正本:
  [../kernel_driver_boundary.md](../kernel_driver_boundary.md),
  [../reference/performance-targets.md](../reference/performance-targets.md)
- 代表テーマ:
  Intel XL710 / E810、SR-IOV、checksum / TSO 等の hardware offload、device-specific benchmark。

### 4. Assurance / threat model / unsafe audit

- 目的:
  archive に残っていた assurance 課題を、実装に近い workstream として追跡可能にする。
- 代表テーマ:
  `threat model` の明文化、allocator / scheduler など高価値コンポーネントの検証、`unsafe audit` の可視化と自動化、loader / capability boundary のレビュー強化。
- 依存する正本:
  [../decisions/ADR-0004-unsafe-confined-to-framework-boundary.md](../decisions/ADR-0004-unsafe-confined-to-framework-boundary.md),
  [../kernel_development_guidelines.md](../kernel_development_guidelines.md)

### 5. Resilience / replication workstream

- 目的:
  checkpoint / restore、secondary promotion、traffic reroute を runtime policy として段階整備する。
- 依存する正本:
  [../reference/resilience-recovery.md](../reference/resilience-recovery.md),
  [../reference/durability.md](../reference/durability.md)
- 代表テーマ:
  checkpoint catalog、driver-domain recovery orchestration、replication manager、promotion trigger、traffic reroute telemetry。

## 進め方の原則

- measurement gate は [../reference/performance-targets.md](../reference/performance-targets.md) の target table を使う。
- resilience work は QoS と混ぜず、[../reference/resilience-recovery.md](../reference/resilience-recovery.md) の vocabulary を使う。
- Secure Boot や measured boot detail は bootloader 側の component detail を正本とし、kernel docs に再定義しない。
- 研究ノートは reference / proposal に保持し、baseline へ昇格させる場合のみ ADR を追加する。

## 旧設計案からの読み替え

| 旧設計案の項目 | 現行の扱い |
| --- | --- |
| 11 フェーズ 1: ブートストラップと基本ランタイム | Boot / runtime bring-up workstream |
| 11.1.1 ブートストラップシーケンス詳細 | [../kernel_boot_sequence.md](../kernel_boot_sequence.md) + bootloader component detail |
| 11 フェーズ 2: Async Executor と割り込み基盤 | Boot / runtime bring-up + [../reference/execution-fairness.md](../reference/execution-fairness.md) |
| 11 フェーズ 3: セルローダーと分離機構 | Boot / runtime bring-up + authority / live update 正本群 |
| 11 フェーズ 4a-4d: 高性能ドライバとネットワーク | Network / datapath maturity + Real NIC enablement |
| 13.1 セキュリティモデルの形式化 | Assurance / threat model / unsafe audit |
| 13.2 性能ベンチマーク計画 | [../reference/performance-targets.md](../reference/performance-targets.md) + Network / datapath maturity |
| 13.3 高可用性設計 | Resilience / replication workstream |
| 13.4 その他の検討事項 | workstream ごとの将来課題メモ |

## 関連文書

- [../kernel_boot_sequence.md](../kernel_boot_sequence.md)
- [../reference/performance-targets.md](../reference/performance-targets.md)
- [../reference/resilience-recovery.md](../reference/resilience-recovery.md)
- [../../bootloader/FUTURE_ROADMAP.md](../../bootloader/FUTURE_ROADMAP.md)
