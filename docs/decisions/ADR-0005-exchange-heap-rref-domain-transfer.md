# ADR-0005: Exchange Heap + RRef Domain Transfer

- Status: Accepted
- Audience: メモリ管理、ドメイン間通信、ランタイム境界を実装する contributor
- Related: [ARCHITECTURE.md](../ARCHITECTURE.md), [Variant A](../design_variants/variant-a-capability-first.md), [開発ガイドライン](../kernel_development_guidelines.md)
- Supersedes: None
- Superseded-By: None
- Date: 2026-04-07

## Context

SAS は同一アドレス空間を共有するが、これを「無制限共有」と解釈すると障害分離と所有権追跡が破綻する。
ドメイン間データ移動は move semantics と回収可能性を保った統一路線が必要である。

## Decision

ドメイン間データ移動方式として以下を採択する。

1. ドメイン間移動データは Exchange Heap を経由する。
2. 所有権は `RRef<T>` で追跡し、move 後の送信元アクセスは不可とする。
3. ドメインクラッシュ時は owner tracking で回収可能にする。
4. `Arc<Mutex<T>>` など共有状態を跨ドメイン標準経路にしない。

## Consequences

- データ所有権のトレース性が上がり、障害時の回収戦略を定義しやすい。
- 設計が share-nothing に寄るため、ロック競合と境界越し共有バグを抑制できる。
- 既存の共有前提実装は移行コストが発生する。
- API設計時に `RRef` と Exchange Heap を前提としたインターフェース統一が必要になる。

## Alternatives Considered

1. **共有メモリを既定経路にする案**
   - 不採用理由: 所有権/回収責務が曖昧化し、障害分離と整合しない。
2. **コピー転送を既定にする案**
   - 不採用理由: 高頻度経路でコピーコストが支配的になりやすい。

## Notes

- zero-copy 経路では `RRef` ベースの所有権移動をレビュー必須項目にする。

## References

- [../ARCHITECTURE.md](../ARCHITECTURE.md)
- [../kernel_development_guidelines.md](../kernel_development_guidelines.md)
