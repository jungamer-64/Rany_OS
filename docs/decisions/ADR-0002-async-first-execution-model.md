# ADR-0002: Async-First Execution Model

- Status: Accepted
- Audience: スケジューラ、I/O、割り込み処理を実装する contributor
- Related: [ARCHITECTURE.md](../ARCHITECTURE.md), [開発ガイドライン](../kernel_development_guidelines.md), [Variant A](../design_variants/variant-a-capability-first.md)
- Supersedes: None
- Superseded-By: None
- Date: 2026-04-07

## Context

ExoRust は高並行I/Oを前提とし、ブロッキング中心の実行モデルではスループットと応答性が両立しない。
加えて、ISR内での重い処理や直接 wake はデッドロック/競合の原因になり得る。

## Decision

実行モデルとして以下を採択する。

1. 実行単位は Future ベースのタスク（Async-First）を標準とする。
2. ISR では event id の enqueue のみを行い、`wake()` は通常コンテキストで deferred 実行する。
3. 公平性の下限は APIC タイマーによる強制プリエンプションで担保する。
4. Fuel や静的解析は最適化であり、進行保証の唯一条件にしない。

## Consequences

- ブロッキングAPIの新規追加は原則禁止となる。
- ISR 実装レビューで「deferred wake」を必須チェック項目にできる。
- Executor / queue 実装で観測性（イベント遅延・滞留）の指標が必要になる。
- 既存コードで直接 wake を呼ぶ経路があれば順次排除対象となる。

## Alternatives Considered

1. **ISR から直接 wake する案**
   - 不採用理由: ロック競合・再入・デッドロックリスクが高い。
2. **完全協調スケジューリングのみ採用する案**
   - 不採用理由: スターベーション下限保証が弱く、実運用での公平性が不足する。

## Notes

- 実装時の判定基準は `kernel_development_guidelines.md` の Async/Await セクションを参照する。

## References

- [../ARCHITECTURE.md](../ARCHITECTURE.md)
- [../kernel_development_guidelines.md](../kernel_development_guidelines.md)
