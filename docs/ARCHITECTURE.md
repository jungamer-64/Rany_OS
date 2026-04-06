# ExoRust アーキテクチャ概要

- Status: Canonical architecture overview
- Audience: 設計判断を行う contributor、レビュー担当者、実装前に前提を確認したい開発者
- Related: [ドキュメントハブ](README.md), [設計ハブ](design-hub.md), [開発ガイドライン](kernel_development_guidelines.md)

この文書は、ExoRust の運用基準となるアーキテクチャ概要です。canonical baseline は
[Variant A: Capability-First Baseline](design_variants/variant-a-capability-first.md) です。

## 1. 設計理念

ExoRust は、次の三原則を採用します。

### 1.1 単一アドレス空間 (Single Address Space: SAS)

- 全ドメインは単一の仮想アドレス空間を共有する。
- SAS は「MMU を捨てる」意味ではない。ガードページ、W^X、IOMMU 連携、Huge Page、物理直線マッピングのためにページングは使い続ける。
- ドメイン間データ移動は Exchange Heap と `RRef` を使い、アドレス空間共有を無制限共有にしない。

### 1.2 単一特権レベル (Single Privilege Level: SPL)

- 全コードは Ring 0 で実行される。
- 直接関数呼び出しは syscall オーバーヘッドを消すが、それ自体は authority を付与しない。
- 権限の根は Safe Rust 単体ではなく、Capability、署名検証、ローダー方針、IOMMU、Framework 境界の組み合わせで定義する。
- 危険 API は `kapi` または Framework 経由で公開し、呼び出し時に Capability を検証する。

### 1.3 非同期中心主義 (Async-First)

- 実行単位は `Future` ベースのタスクとする。
- I/O 待機は `await` で表現し、ブロッキング API を避ける。
- 公平性の最終担保は APIC タイマーによる強制プリエンプションで行う。
- Fuel や静的解析は最適化であり、停止性の唯一の前提にはしない。

## 2. カーネルモジュール境界

現行カーネルの正規モジュールグラフは `kernel/src/lib.rs` を起点に管理する。

- ブート経路は `kernel/src/main.rs` -> `kernel/src/boot/` -> `boot::enter()` に集約する。
- `kernel/src/kapi/` は認可済みの Kernel API 公開境界とする。
- `kernel/src/resource_registry/` は runtime-owned resource state の唯一の所有者とする。
- `kernel/src/fs/` はカーネル内ファイルシステム実装の正規配置とし、cross-tree path include を使わない。
- `kernel/src/host_support/` は test/bench 専用の軽量差し替え面として本番経路と分離する。
- ドライバ責務との切り分けは [kernel_driver_boundary.md](kernel_driver_boundary.md) に従う。

## 3. メモリと DMA

### 3.1 階層型アロケータ

- Tier 1: 物理フレーム管理
- Tier 2: グローバルヒープ
- Tier 3: Per-core cache

この三層をベースに、NUMA ローカル割り当てと per-core 高速化を両立する。

### 3.2 Exchange Heap

- ドメイン間で移動するデータは Exchange Heap に置く。
- `RRef<T>` により所有者を追跡し、送信元は move 後にアクセス権を失う。
- ドメインクラッシュ時は owner tracking を用いて回収する。

### 3.3 DMA と IOMMU

- DMA は IOMMU を必須前提とする。
- ドライバは `alloc_dma_buffer()` のような Framework API 経由でのみ DMA バッファを取得する。
- 任意アドレス DMA、IOMMU バイパス、DMA 中の CPU 側アクセスは設計上禁止する。

## 4. ドメイン分離と authority

### 4.1 authority の根

ExoRust では、authority の根は次の組み合わせで定義する。

- Capability とその delegation / revoke モデル
- 署名済みセルとローダー検証
- `#[repr(C)]` 境界と opaque handle
- IOMMU による DMA 制限
- Framework 層に閉じた `unsafe`

直接関数呼び出しは高速化の仕組みであり、無権限アクセスを正当化しない。

### 4.2 ドメイン境界 ABI

- ドメイン境界を跨ぐ公開型は `#[repr(C)]` を必須とする。
- opaque handle、Capability token、固定 ABI のメッセージ、シリアライズ状態を正規面にする。
- `#[repr(Rust)]`、`impl Trait`、`dyn Trait`、vtable に依存する値、関数ポインタを境界 ABI にしない。
- 型ハッシュは互換性の検出に使うが、Rust ABI の不安定性そのものを消す仕組みとはみなさない。

## 5. Async 実行と割り込み

- 各 CPU コアに executor を配置する。
- ISR はイベント ID を deferred wake キューへ積み、通常コンテキストで `wake()` を行う。
- ポーリングと割り込みは workload に応じて切り替える。
- share-nothing を優先し、共有状態が必要な場合は owner を明確にした message passing を使う。

## 6. ライブアップデートの制約

ライブアップデートは「セル全体の差し替え」と「状態移行」を前提とする。GOT のアトミックスワップだけで安全とはみなさない。

### 6.1 持ち越し可能な状態

- `#[repr(C)]` の状態構造体
- opaque handle
- Capability token
- バージョン付きシリアライズ状態
- ABI が固定されたバッファ

### 6.2 持ち越し禁止の状態

- `Future` の内部状態
- `dyn Trait` と vtable
- 関数ポインタ
- 旧コード由来の drop glue
- `#[repr(Rust)]` の型レイアウトに依存する値

### 6.3 更新手順

- 新セルを別領域にロードする。
- quiescent state を待つ。
- 旧セルから移行可能状態を export する。
- 新セルで import して切り替える。
- in-flight 参照が消えたことを確認して旧セルを回収する。

## 7. 障害分離と回復

- 通常系のエラーは `Result` で返す。
- panic はドメイン境界で封じ込め、呼び出し側には `Err` として返す。
- ガードページでスタックオーバーフローを捕捉する。
- 共有ロックは `PoisonLock<T>` を使い、パニック後の連鎖障害を防ぐ。

## 8. セキュリティモデル

### 8.1 基本方針

- メモリ安全と authority は別物として扱う。
- Safe Rust はメモリ安全の基盤だが、権限制御は Capability とローダー方針で行う。
- 本番では署名検証済みのセルのみをロードする。
- IOMMU が使えない環境では DMA を伴う通常運用を前提にしない。

### 8.2 ハードウェア支援の位置付け

- MPK/PKU/PKS 系は使える環境では追加防御にできる。
- canonical baseline では、これらを主分離機構や correctness の前提にしない。
- ハードウェア支援を強く使う案は
  [Variant B](design_variants/variant-b-hybrid-hardware-accelerated.md) と
  [Variant C](design_variants/variant-c-pks-mandatory.md)
  に分離して扱う。

## 9. 関連文書

- ドキュメントハブ:
  [README.md](README.md)
- 設計比較ハブ:
  [design-hub.md](design-hub.md)
- 開発ガイドライン:
  [kernel_development_guidelines.md](kernel_development_guidelines.md)
- Capability 設計:
  [capabilities.md](capabilities.md)
- 設計サンプル:
  [exorust_design/README.md](exorust_design/README.md)
