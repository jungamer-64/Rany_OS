# Durability / Persistence Reference

- Status: Reference
- Audience: ストレージ、永続性、ブート時リカバリ経路を確認したい contributor
- Related: [../architecture.md](../architecture.md), [resilience-recovery.md](resilience-recovery.md), [api-reference.md](api-reference.md), [lru-block-cache.md](lru-block-cache.md)

この文書は ExoRust における durability / persistence の現行 reference です。競合時は
[../architecture.md](../architecture.md) と
[../kernel-development-guidelines.md](../kernel-development-guidelines.md)
を優先してください。

## 位置付け

- durability は公開 `fs` API の上位互換ではなく、その下の永続性層として扱う。
- `Canonical requirement`:
  WAL、recovery / checkpoint、PMEM persist ordering（`clwb` + `sfence`）。
- `Canonical target`:
  CoW snapshot control、DAX / PMEM direct mapping、snapshot rollback。
- `Canonical target` は採択済みであり、未実装部分は `implementation pending` と明記する。

## 現行実装

### 1. Durability 初期化

- 実装入口:
  [../../kernel/src/durability/mod.rs](../../kernel/src/durability/mod.rs)
- `crate::durability::init()` は `pmem::init_from_nfit()` と `wal::init_global_wal()` を起動する。
- ブート時の backend 設定と recovery は非同期に完了する。永続 WAL を要求した設定が失敗した場合は起動を完了しない。

### 2. WAL / recovery / checkpoint

- 実装:
  [../../kernel/src/durability/wal/mod.rs](../../kernel/src/durability/wal/mod.rs)
- WAL の受付、記録、回復、checkpoint は durability 層が所有する。block backend は受付時のデバイス所有者を保持し、DMA 完了・mapping の終了・デバイス flush を確認する。
- transaction の準備は排他的な受付と必要な割当て・容量を確保する。準備済み owner の破棄は未公開の操作を取り消す。commit の完了通知は記録の書込み、data flush、root の公開、root flush の後に返す。volatile の完了通知は永続化を意味しない。
- root は世代と checksum を持つ二つのページで管理する。回復は有効な root が公開した完全な transaction のみを対象とする。非空の破損媒体を暗黙に初期化しない。checkpoint は home storage の永続化を確認してから別 bank の root を公開する。
- 書込み開始後の失敗・取消ではデバイスと未完了の intent を保持する。公開済みか不明な結果から新しい受付や再試行の権限を復元しない。共有 lock は I/O の待機中に保持しない。
- memfs の変更操作は journal と同じ順序で直列化する。変更前の受付失敗と、メモリ変更後の未完了を型付きで区別する。後者の取消・失敗は intent を保持し、回復まで後続の変更を受け付けない。ブートの replay は memfs に実際の変更を適用する。memfs は永続 home storage を持たないため、その replay を checkpoint 完了とは扱わない。

### 3. PMEM persist ordering

- 実装:
  [../../kernel/src/durability/pmem/mod.rs](../../kernel/src/durability/pmem/mod.rs)
- `Canonical requirement`:
  - `init_from_nfit()`
  - `register_region()`
  - `allocate()`
  - `persist_range()`
  - `persist_ordered()`
- `persist_range()` は cache line flush の後に fence を行う。
- `persist_ordered()` は log 領域を先に、payload を後に永続化する順序 helper として扱う。
- PMEM 領域の discovery は ACPI NFIT 由来で fail-open する。

### 4. CoW / snapshot

- `Canonical target`:
  CoW snapshot は WAL / recovery と競合する代替案ではなく、整合性維持と rollback を補助する採択済み target である。
- 現行 tree では memfs / page 系に CoW / snapshot 的な実装が存在する。
- `implementation pending`:
  system-wide snapshot control、snapshot metadata ABI、rollback orchestration。

### 5. DAX / PMEM direct mapping

- `Canonical target`:
  PMEM 上のファイルまたは永続オブジェクトを、ページキャッシュを必須にせず直接参照できる mapping handle を提供する。
- `implementation pending`:
  DAX handle の公開 ABI、permission / lifetime policy、snapshot / recovery との整合。
- DAX / PMEM mapping を導入しても、ordering と recovery の authoritative source は durability 層に残す。

## Canonical surface

| Surface | Level | Notes |
| --- | --- | --- |
| WAL append / commit / recover / checkpoint | Canonical requirement | durability 層が authoritative source |
| PMEM persist helpers | Canonical requirement | `persist_range()` / `persist_ordered()` |
| Snapshot control | Canonical target / implementation pending | CoW rollback と復元点管理を含む |
| DAX / PMEM mapping handle | Canonical target / implementation pending | direct mapping だが durability ordering は bypass しない |

## 非目標

- VFS 全体に対する単一 API だけで durability の全責務を表現すること
- subsystem ごとに durability ordering を再定義すること
- snapshot や DAX を WAL / recovery から切り離した独立契約として扱うこと

## 関連文書

- [../architecture.md](../architecture.md)
- [../kernel-development-guidelines.md](../kernel-development-guidelines.md)
- [resilience-recovery.md](resilience-recovery.md)
- [api-reference.md](api-reference.md)
- [lru-block-cache.md](lru-block-cache.md)
