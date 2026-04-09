# ADR-0004: Unsafe Confined to Framework Boundary

- Status: Accepted
- Audience: カーネル実装者、ドライバ実装者、セキュリティレビュー担当
- Related: [開発ガイドライン](../kernel-development-guidelines.md), [architecture.md](../architecture.md), [Variant A](../design_variants/variant-a-capability-first.md)
- Supersedes: None
- Superseded-By: None
- Date: 2026-04-07

## Context

ExoRust は Safe Rust を基盤にするが、低レイヤ（MMIO、割り込み、DMA、FFI）では `unsafe` が不可避な箇所がある。
`unsafe` がアプリ/サービス側に拡散すると TCB が肥大化し、レビュー困難性が上がる。

## Decision

`unsafe` の配置方針として、以下を採択する。

1. `unsafe` は Framework 層と低レベル HAL に集約する。
2. アプリケーションセル／サービスセル／通常ドライバ面には Safe API を提供する。
3. ドメイン境界の公開面では raw pointer を露出しない。
4. 例外的に `unsafe` が必要な場合、根拠コメントとレビューを必須にする。

## Consequences

- TCB の範囲が明確化され、監査しやすくなる。
- API設計時に「safe wrapperの責務」が増える。
- 一時的に実装コストは増えるが、長期保守性は向上する。
- review checklist に `unsafe` 境界確認が常設される。

## Alternatives Considered

1. **各モジュールで必要に応じて `unsafe` を許可する案**
   - 不採用理由: 境界が曖昧になり、監査コストが指数的に増える。
2. **`unsafe` を完全禁止する案**
   - 不採用理由: OS/Kernel の実装要件（MMIO/割り込み/DMA）を満たせない。

## Notes

- `unsafe` が必要な最小面を維持するため、定期的な削減監査を行う。

## References

- [../kernel-development-guidelines.md](../kernel-development-guidelines.md)
- [../architecture.md](../architecture.md)
