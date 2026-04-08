# Durability / Persistence Reference

- Status: Reference
- Audience: ストレージ、永続性、ブート時リカバリ経路を確認したい contributor
- Related: [../ARCHITECTURE.md](../ARCHITECTURE.md), [resilience-recovery.md](resilience-recovery.md), [api-reference.md](api-reference.md), [lru-block-cache.md](lru-block-cache.md)

この文書は ExoRust における durability / persistence の現行 reference です。競合時は
[../ARCHITECTURE.md](../ARCHITECTURE.md) と
[../kernel_development_guidelines.md](../kernel_development_guidelines.md)
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
- durability 初期化はブート時に `kernel_main` から呼び出され、WAL backend 設定、recovery、checkpoint と接続される。

### 2. WAL / recovery / checkpoint

- 実装:
  [../../kernel/src/durability/wal/mod.rs](../../kernel/src/durability/wal/mod.rs)
- `Canonical requirement`:
  - `init_global_wal()`
  - `begin()`
  - `append()`
  - `commit()`
  - `recover_from_backend()`
  - `checkpoint()`
  - `set_backend_nvme_raw()`
- 現行 backend の reference 実装は NVMe raw backend である。
- canonical な durability contract は「recovery / checkpoint を durability 層で扱う」ことであり、個別ファイルシステムが独自に永続化順序を再定義することではない。

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

## 旧設計案からの読み替え

| 旧設計案の項目 | 現行の扱い |
| --- | --- |
| WAL | Canonical requirement |
| PMEM persist (`clwb` + `sfence`) | Canonical requirement |
| CoW / snapshot | Canonical target |
| DAX / PMEM file mapping | Canonical target / implementation pending |

## 関連文書

- [../ARCHITECTURE.md](../ARCHITECTURE.md)
- [../kernel_development_guidelines.md](../kernel_development_guidelines.md)
- [resilience-recovery.md](resilience-recovery.md)
- [api-reference.md](api-reference.md)
- [lru-block-cache.md](lru-block-cache.md)
