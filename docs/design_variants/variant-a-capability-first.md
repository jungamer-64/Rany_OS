# Variant A: Capability-First Baseline

- Status: Canonical baseline
- Audience: 設計判断を固定したい contributor、実装者、レビュー担当者
- Related: [ドキュメントハブ](../README.md), [設計ハブ](../design-hub.md), [アーキテクチャ概要](../ARCHITECTURE.md)

ExoRust の canonical baseline です。分離の主軸は Capability、型安全な境界、署名済みセル、IOMMU、Framework 境界に置きます。MPK/PKU/PKS 系は使える CPU での追加防御であり、correctness の前提にしません。

| 項目 | 方針 |
|------|------|
| authority の根 | Capability、署名検証、ローダー方針、IOMMU、Framework 境界 |
| 必要 CPU / HW | x86_64、IOMMU 必須。MPK/PKU/PKS は任意 |
| live update をまたげるもの | `#[repr(C)]` 状態、handle、token、バージョン付きシリアライズ状態 |
| 採択済み target | CoW snapshot、DAX / PMEM mapping、replication、dynamic tracing |
| 位置付け | 既定案 |

## 1. SAS/SPL の前提

- SAS を採用し、TLB フラッシュとデータコピーを減らす。
- SPL を採用し、syscall ではなく直接関数呼び出しを使う。
- ただし、直接呼び出しは高速化の仕組みであり、authority の証明ではない。

## 2. 権限モデル

- privileged operation は Capability を必須とする。
- `cell.swap`、`mmio.write`、DMA/IOMMU 制御、他ドメイン観測、driver domain 管理は Capability で守る。
- delegation / revoke / in-flight drain は [capabilities.md](../capabilities.md) のモデルに従う。

## 3. ドメイン境界 ABI

- 公開型は `#[repr(C)]` を必須とする。
- opaque handle、Capability token、固定 ABI のメッセージ、明示的なシリアライズ状態を正規面にする。
- `#[repr(Rust)]`、`dyn Trait`、`impl Trait`、関数ポインタ、vtable 依存値を境界 ABI にしない。
- 型ハッシュは「互換性を検出する仕組み」であり、「Rust ABI を安定化する仕組み」ではない。

## 4. unsafe / Framework 境界

- `unsafe` は Framework、低レベルメモリ管理、DMA/IOMMU、例外/割り込み、最下層ドライバ HAL に集約する。
- サービスセルやアプリケーションセルは Safe API のみを使う。
- higher layer では raw pointer や MMIO register access を露出しない。

## 5. Async / プリエンプション方針

- 実行単位は `Future` ベースのタスクとする。
- ISR は event queue に積むだけにし、通常コンテキストで deferred wake する。
- APIC タイマーによる強制プリエンプションを公平性の下限とする。
- executor locality は同一 NUMA ノードを優先する。
- adaptive polling / interrupt switching と C-state 制御を baseline に含める。
- Fuel や静的解析は追加最適化であり、進行保証の唯一条件にしない。

## 6. メモリ / DMA

- ドメイン間データは Exchange Heap と `RRef` で移動する。
- DMA は `alloc_dma_buffer()` のような Framework API と IOMMU を必須にする。
- `Arc<Mutex<T>>` による跨ドメイン共有を既定経路にしない。
- NUMA ローカル割り当てと per-core cache を優先する。
- `alloc_on_numa_node(node_id, layout)` 相当の明示ノード指定を canonical target interface とする。
- WAL / PMEM persist ordering は requirement、CoW snapshot と DAX / PMEM direct mapping は canonical target とする。

## 7. ライブアップデート

- セルの差し替えは、ロード、quiescent state、state export/import、参照排出、旧セル回収の順で行う。
- GOT の切替だけで安全とはみなさない。
- 持ち越し可能:
  `#[repr(C)]` 状態、handle、token、バージョン付きシリアライズ状態
- 持ち越し禁止:
  `Future` 内部状態、`dyn Trait` / vtable、関数ポインタ、旧コード由来 drop glue

## 8. 障害回復

- 通常エラーは `Result` で返す。
- panic はドメイン境界で封じ込め、呼び出し側には `Err` として通知する。
- ガードページと `PoisonLock<T>` を使って連鎖障害を抑える。
- driver domain は restart policy と fault history を持つ recovery unit とする。
- double panic 検出と dedicated IST stack による double fault hardening を baseline に含める。
- checkpoint / recovery / replication は canonical target とし、未実装部分は `implementation pending` と明記する。

## 9. セキュリティ

- memory safety と authority を分離して考える。
- Safe Rust は memory corruption の抑止、Capability は権限制御、IOMMU は DMA 制御、署名検証はロード制御を担う。
- MPK/PKU/PKS は使える CPU で追加防御に使えるが、未対応 CPU でも同じ安全モデルで成立しなければならない。

## 10. 対象ハードウェア

- 主対象は x86_64 サーバー / VM 環境。
- IOMMU は必須。
- NUMA トポロジ情報、PMU、ACPI power management は推奨前提。
- MPK/PKU/PKS は optional feature として扱う。

## 関連文書

- [../README.md](../README.md)
- [../design-hub.md](../design-hub.md)
- [../kernel_development_guidelines.md](../kernel_development_guidelines.md)
