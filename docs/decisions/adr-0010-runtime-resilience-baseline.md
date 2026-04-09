# ADR-0010: Runtime Resilience Baseline

- Status: Accepted
- Audience: runtime 設計者、driver-domain 実装者、運用担当者
- Related: [../architecture.md](../architecture.md), [../reference/resilience-recovery.md](../reference/resilience-recovery.md), [ADR-0007](adr-0007-variant-a-as-canonical-baseline.md)
- Supersedes: None
- Superseded-By: None
- Date: 2026-04-09

## Context

旧設計案の checkpoint / recovery / replication / auto-restart は archive 側に残り、
現行 docs では高可用性や resilience が QoS の非目標に近い位置に押し戻されていた。

一方で、driver domain の restart policy、fault history、watchdog / heartbeat、
WAL checkpoint は実装や設計としてすでに存在する。

## Decision

runtime resilience baseline を次のように定義する。

1. panic containment、watchdog / heartbeat、driver-domain restart policy、durability checkpoint は canonical requirement とする。
2. domain / cell checkpoint、replication、secondary promotion、traffic reroute は canonical target とする。
3. resilience は QoS と分離し、専用 reference で扱う。
4. 未実装部分は `implementation pending` と明記し、採択済み target として扱う。

## Consequences

- checkpoint / restart / replication の責務が runtime policy の中で明確になる。
- driver-domain recovery を baseline の一部としてレビューできる。
- QoS 文書が resource accounting に集中できる。

## Alternatives Considered

1. **高可用性を runtime QoS の一部に残す案**
   - 不採用理由: 資源制御と recovery policy が混在する。
2. **restart policy だけを baseline にし、replication は別扱いのままにする案**
   - 不採用理由: 旧設計案から現行 docs への読み替えが不完全になる。
3. **resilience を driver domain 限定にする案**
   - 不採用理由: checkpoint / replication を cell / domain へ拡張できなくなる。

## Notes

- `Canonical target` は採択済み target であり、実装段階の明示を伴う。

## References

- [../reference/resilience-recovery.md](../reference/resilience-recovery.md)
- [../architecture.md](../architecture.md)
