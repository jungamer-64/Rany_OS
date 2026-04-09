# ADR-0009: Observability Baseline Includes Tracing + Reproducibility

- Status: Accepted
- Audience: observability / debug 設計者、レビュー担当者、運用担当者
- Related: [../architecture.md](../architecture.md), [../reference/observability-debug.md](../reference/observability-debug.md), [ADR-0007](adr-0007-variant-a-as-canonical-baseline.md)
- Supersedes: None
- Superseded-By: None
- Date: 2026-04-09

## Context

現行 docs では structured log、watchdog、backtrace は baseline に入っていたが、
tracepoint、ring buffer export、safe dynamic tracing、reproducible build は
補助資料側に散らばっていた。

実装側には `diag`、`watchdog`、`debug`、`profiler` が存在し、可観測性ファミリーとしての責務は
すでに成立している。

## Decision

observability baseline を次のように定義する。

1. structured log、serial structured log、watchdog、metrics / snapshot、backtrace、static tracepoint、trace ring buffer export を canonical requirement とする。
2. safe dynamic tracing、reproducible release artifacts、panic dump export、trace query / control surface を canonical target とする。
3. KGDB / GDB transport detail は component detail とするが、boot policy と整合していること自体は baseline requirement とする。

## Consequences

- tracepoint と serial log が baseline の一部として追跡可能になる。
- dynamic tracing と reproducibility は採択済み target として整理される。
- observability family の責務境界を docs で統一しやすくなる。

## Alternatives Considered

1. **tracepoint / reproducibility を補助資料側のまま維持する案**
   - 不採用理由: 旧設計案からの読み替えが曖昧なまま残る。
2. **dynamic tracing を即 requirement にする案**
   - 不採用理由: 能力境界と loader policy の設計がまだ段階整備中。
3. **GDB / KGDB も全 build 必須にする案**
   - 不採用理由: bring-up / debug path と通常運用 path の区別が必要。

## Notes

- dynamic tracing は eBPF 互換を要求しない。safe tracing として扱う。

## References

- [../reference/observability-debug.md](../reference/observability-debug.md)
- [../architecture.md](../architecture.md)
