# ADR-0011: Locality / Power / Fault Hardening Baseline

- Status: Accepted
- Audience: scheduler / mm / power / panic path の設計者、レビュー担当者
- Related: [../architecture.md](../architecture.md), [../kernel-development-guidelines.md](../kernel-development-guidelines.md), [ADR-0007](adr-0007-variant-a-as-canonical-baseline.md)
- Supersedes: None
- Superseded-By: None
- Date: 2026-04-09

## Context

旧設計案には NUMA locality、task affinity、adaptive C-state、double panic 検出、
IST を使う double fault hardening が細かく書かれていたが、現行 docs では一部だけが残っていた。

実装側には `mm::numa`、`power`、panic handler、IST を持つ interrupt path が存在するため、
これらを baseline requirement / target として再整理する価値がある。

## Decision

baseline に次を含める。

1. NUMA ローカル割り当て、same-node-first executor locality、adaptive polling / interrupt switching を baseline に含める。
2. task affinity mask と明示 NUMA ノード指定割り当ては canonical target interface とする。
3. double panic 検出、dedicated IST stack、minimal fatal fault path を canonical requirement とする。
4. C-state 制御は baseline に含めるが、詳細ヒューリスティクスは実装差を許容する。

## Consequences

- NUMA / power / panic hardening が archive ではなく現行正本で追えるようになる。
- 旧来の cross-node steal 中心の表現を same-node-first scheduling に寄せて整理できる。
- fatal path の設計制約がレビュー基準として明文化される。

## Alternatives Considered

1. **NUMA / power / fault hardening を参考実装扱いのままにする案**
   - 不採用理由: 実装と docs の乖離が残る。
2. **すべてを即 requirement にする案**
   - 不採用理由: task affinity や一部 locality API は段階整備が前提。
3. **power management を完全に component detail に落とす案**
   - 不採用理由: polling coexistence と idle policy は runtime baseline に影響する。

## Notes

- Variant B/C の optional defense には触れず、Variant A baseline の厚みを増す ADR とする。

## References

- [../architecture.md](../architecture.md)
- [../kernel-development-guidelines.md](../kernel-development-guidelines.md)
