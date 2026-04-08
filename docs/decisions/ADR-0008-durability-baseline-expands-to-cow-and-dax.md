# ADR-0008: Durability Baseline Expands to CoW Snapshot + DAX

- Status: Accepted
- Audience: durability 設計者、ストレージ実装者、レビュー担当者
- Related: [../ARCHITECTURE.md](../ARCHITECTURE.md), [../reference/durability.md](../reference/durability.md), [ADR-0007](ADR-0007-variant-a-as-canonical-baseline.md)
- Supersedes: None
- Superseded-By: None
- Date: 2026-04-09

## Context

旧設計案では CoW snapshot と DAX / PMEM direct access を durability 設計の一部として扱っていたが、
現行 docs では保留中の論点または局所実装として弱く表現されていた。

一方で、WAL / checkpoint / PMEM persist ordering はすでに baseline として定着しており、
snapshot / DAX を保留中の論点のように書き続けると、採択済みの設計目標と archive の関係が曖昧になる。

## Decision

durability baseline を次のように拡張する。

1. WAL、recovery / checkpoint、PMEM persist ordering は引き続き canonical requirement とする。
2. CoW snapshot control と DAX / PMEM direct mapping は canonical target として採択する。
3. 未実装部分は `implementation pending` と明記する。
4. snapshot / DAX を導入しても、ordering と recovery の authoritative source は durability 層に残す。

## Consequences

- archive 由来の durability 論点が現行正本へ戻り、読み替えが明確になる。
- filesystem 局所実装と system-wide durability contract を区別しやすくなる。
- DAX / snapshot まわりの API 整備と recovery 整合は後続実装タスクとして明示される。

## Alternatives Considered

1. **WAL / PMEM だけを baseline に残す案**
   - 不採用理由: 旧設計案との読み替えが曖昧なまま残り、CoW / DAX を再び保留扱いに押し戻してしまう。
2. **CoW / DAX を即 requirement にする案**
   - 不採用理由: 採択判断は済ませたいが、公開 ABI と運用手順はまだ段階整備が必要。
3. **filesystem ローカル設計に委ねる案**
   - 不採用理由: durability contract が subsystem ごとに分裂する。

## Notes

- `Canonical target` は採択済みの基準であり、roadmap 専用語ではない。

## References

- [../reference/durability.md](../reference/durability.md)
- [../ARCHITECTURE.md](../ARCHITECTURE.md)
