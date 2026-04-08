# Durability / Persistence Reference

- Status: Reference
- Audience: ストレージ、永続性、ブート時リカバリ経路を確認したい contributor
- Related: [../ARCHITECTURE.md](../ARCHITECTURE.md), [api-reference.md](api-reference.md), [lru-block-cache.md](lru-block-cache.md)

この文書は ExoRust における durability / persistence の現行 reference です。競合時は
[../ARCHITECTURE.md](../ARCHITECTURE.md) と
[../kernel_development_guidelines.md](../kernel_development_guidelines.md)
を優先してください。

## 位置付け

- durability は公開 `fs` API の上位互換ではなく、その下の永続性層として扱う。
- 現行の reference 対象は WAL と PMEM persist ordering である。
- CoW / snapshot は一部ファイルシステム実装で使えても、system-wide durability contract の唯一前提にはしない。

## 現行実装

### 1. Durability 初期化

- 実装入口:
  [../../kernel/src/durability/mod.rs](../../kernel/src/durability/mod.rs)
- `crate::durability::init()` は `pmem::init_from_nfit()` と `wal::init_global_wal()` を起動する。
- durability 初期化はブート時に `kernel_main` から呼び出され、WAL backend 設定、recovery、checkpoint と接続される。

### 2. WAL

- 実装:
  [../../kernel/src/durability/wal/mod.rs](../../kernel/src/durability/wal/mod.rs)
- 現行の公開入口:
  - `init_global_wal()`
  - `begin()`
  - `append()`
  - `commit()`
  - `recover_from_backend()`
  - `checkpoint()`
  - `set_backend_nvme_raw()`
- 現行 backend の reference 実装は NVMe raw backend である。
- canonical な durability contract は「recovery / checkpoint を durability 層で扱う」ことであり、個別ファイルシステムが独自に永続化順序を再定義することではない。

### 3. PMEM

- 実装:
  [../../kernel/src/durability/pmem/mod.rs](../../kernel/src/durability/pmem/mod.rs)
- 現行の公開入口:
  - `init_from_nfit()`
  - `register_region()`
  - `allocate()`
  - `persist_range()`
  - `persist_ordered()`
- `persist_range()` は cache line flush の後に fence を行う。
- `persist_ordered()` は log 領域を先に、payload を後に永続化する順序 helper として扱う。
- PMEM 領域の discovery は ACPI NFIT 由来で fail-open する。

### 4. CoW / snapshot の扱い

- memfs / page 系には CoW と snapshot 的な実装が存在する。
- これはファイルシステム局所の実装技法であり、WAL や PMEM ordering の代替ではない。
- 旧設計案にあった CoW filesystem / DAX / PMEM file mapping の全体契約は、現行 canonical では未採択である。

## 非目標

- VFS 全体に対する統一 durability ABI
- 全ファイルシステムに CoW / journal / snapshot を義務付けること
- 公開 DAX ABI を現行 canonical として固定すること
- roadmap 上の durability 評価計画を、そのまま現行仕様へ昇格させること

## 旧設計案からの読み替え

| 旧設計案の項目 | 現行の扱い |
| --- | --- |
| WAL | 現行 reference / 実装あり |
| PMEM persist (`clwb` + `sfence`) | 現行 reference / 実装あり |
| CoW / snapshot | ファイルシステム局所の実装技法。canonical durability contract ではない |
| DAX / PMEM file mapping | 将来課題。現行 canonical では未採択 |

## 関連文書

- [../ARCHITECTURE.md](../ARCHITECTURE.md)
- [../kernel_development_guidelines.md](../kernel_development_guidelines.md)
- [api-reference.md](api-reference.md)
- [lru-block-cache.md](lru-block-cache.md)
