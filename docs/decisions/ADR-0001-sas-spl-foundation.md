# ADR-0001: SAS/SPL Foundation

- Status: Accepted
- Audience: カーネル設計者、レビュー担当者、境界APIを設計する実装者
- Related: [ARCHITECTURE.md](../ARCHITECTURE.md), [Variant A](../design_variants/variant-a-capability-first.md), [開発ガイドライン](../kernel_development_guidelines.md)
- Supersedes: None
- Superseded-By: None
- Date: 2026-04-07

## Context

ExoRust は syscall 境界前提の分離ではなく、Single Address Space（SAS）と Single Privilege Level（SPL）を採用する。
一方で、SAS/SPL は「無制限共有」や「無条件の権限付与」を意味しない。

- パフォーマンス上、TLB フラッシュやデータコピーの削減が重要
- 安全上、authority は呼び出し経路ではなく明示的モデルで管理する必要がある
- ドメイン境界とDMA境界の統制を崩さない前提が必要

## Decision

ExoRust の基盤方針として、次を採択する。

1. 仮想メモリ設計は SAS を前提とする。
2. 実行権限モデルは SPL を前提とする（Ring 0 同居）。
3. 直接関数呼び出しは高速化手段であり、authority の証明には使わない。
4. 権限の根は Capability・署名検証・IOMMU・Framework境界の組み合わせで定義する。

## Consequences

- 既存/新規設計は「SAS/SPLでも境界は消えない」前提でレビューされる。
- syscall境界に依存した設計（権限境界の代替）は不採用となる。
- ドメイン間通信は別ADR（Exchange Heap + `RRef`）で統制する。
- セキュリティ検証はAPI呼び出し経路ではなくCapability検証を主軸に行う。

## Alternatives Considered

1. **Process-per-address-space を標準にする案**
   - 不採用理由: 目標とする低レイテンシと実装簡素化（直接呼び出し）に反する。
2. **SPL ではなく syscall 境界を必須にする案**
   - 不採用理由: ExoRust の設計理念（言語・型安全境界を主軸）と整合しない。

## Notes

- 本ADRは基盤方針であり、詳細実装方針は後続ADR（0002〜0006）で具体化する。

## References

- [../ARCHITECTURE.md](../ARCHITECTURE.md)
- [../design-hub.md](../design-hub.md)
