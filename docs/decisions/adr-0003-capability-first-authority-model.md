# ADR-0003: Capability-First Authority Model

- Status: Accepted
- Audience: 権限管理、KAPI、ExoShell を実装する contributor
- Related: [capabilities.md](../capabilities.md), [architecture.md](../architecture.md), [Variant A](../design_variants/variant-a-capability-first.md)
- Supersedes: None
- Superseded-By: None
- Date: 2026-04-07

## Context

SPL 環境では、単なる関数呼び出し到達性を authority 判定に使うと境界が崩れる。
危険操作（`cell.swap`, `mmio.write`, DMA/IOMMU 制御、他ドメイン観測）は明示的な権限体系で統制する必要がある。

## Decision

権限モデルとして Capability-first を採択する。

1. 危険APIは Capability を必須にする。
2. 付与・剥奪・委譲（grant/revoke/delegation）は明示操作とし、監査可能にする。
3. 権限の根は Capability 単体ではなく、署名検証・IOMMU・Framework境界と組み合わせる。
4. 直接呼び出し可能性は権限証明として扱わない。

## Consequences

- KAPI設計時に「必要Capability」を宣言する運用が必要になる。
- レビュー観点として least privilege を明示できる。
- 一時委譲や有効期限付きトークンの運用設計が必要になる。
- 一括管理のため capability ドキュメント整備コストが増える。

## Alternatives Considered

1. **ロールベースのみ（Capabilityなし）で管理する案**
   - 不採用理由: 細粒度制御と監査性が不足する。
2. **呼び出し元モジュール名に依存する案**
   - 不採用理由: 境界の明確性が低く、変更に脆い。

## Notes

- ExoShell 側 API の運用指針は `docs/capabilities.md` を正本とする。

## References

- [../capabilities.md](../capabilities.md)
- [../architecture.md](../architecture.md)
