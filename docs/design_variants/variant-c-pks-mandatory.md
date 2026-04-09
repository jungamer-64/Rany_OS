# Variant C: PKS-Mandatory High-Assurance SKU

- Status: Research / high-assurance SKU option
- Audience: 高保証 SKU や強制分離要件を検討する contributor
- Related: [ドキュメントハブ](../README.md), [設計比較ガイド](../design-overview.md), [Variant A](variant-a-capability-first.md), [Hardware-Assisted Security Notes](hardware-assisted-security-notes.md)

高保証 SKU 向けの研究案です。Supervisor 向け保護キー相当のハードウェア、IOMMU、署名済みロードを必須化し、ドメイン遷移とデータ配置を最も厳しく制約します。

| 項目 | 方針 |
|------|------|
| authority の根 | Capability、署名検証、ローダー方針、IOMMU、Supervisor 向け保護キー相当 |
| 必要 CPU / HW | x86_64、IOMMU、Supervisor 向け保護キー相当、セキュアブート推奨 |
| live update をまたげるもの | `#[repr(C)]` 状態、handle、token、バージョン付きシリアライズ状態のみ |
| 位置付け | 高保証 SKU / 研究用 |

## 1. SAS/SPL の前提

- SAS/SPL は維持する。
- ドメイン遷移は検証済みトランポリン経由に限定する。
- protection key の設定は every-transition で明示的に切り替える。

## 2. 権限モデル

- Capability は引き続き policy root とする。
- その上で、hardware protection を mandatory enforcement layer として重ねる。
- 直接関数呼び出しと権限制御を厳密に分離し、unchecked な cross-domain path を認めない。

## 3. ドメイン境界 ABI

- 公開面は `#[repr(C)]`、opaque handle、token、固定 ABI メッセージに限定する。
- `dyn Trait`、`impl Trait`、関数ポインタ、`#[repr(Rust)]` 型は境界越え禁止とする。
- `RRef` を使う場合も、跨バージョンや跨信頼レベルでは ABI 固定データバッファに限定する。

## 4. unsafe / Framework 境界

- `unsafe` は Framework に閉じる。
- protection key 操作、トランポリン、DMA/IOMMU、例外ハンドラは最小 TCB として監査対象にする。
- ドライバやサービスセルに raw hardware control を露出しない。

## 5. Async / プリエンプション方針

- Future ベース executor を使う。
- ISR は deferred wake を維持する。
- 公平性は APIC タイマーで担保する。
- protection key 切替コストを前提に、短い cross-domain hop を増やしすぎない設計にする。

## 6. メモリ / DMA

- Exchange Heap と `RRef` は維持するが、データ機密クラスごとに保護領域を分ける。
- DMA は IOMMU を必須にし、device domain ごとの mapping を厳密に管理する。
- secret material は一般データとは別クラスに置き、必要に応じて cache partitioning を併用する。

## 7. ライブアップデート

- in-place hot swap は最も保守的に扱う。
- 持ち越し可能なのは `#[repr(C)]` 状態、handle、token、バージョン付きシリアライズ状態のみ。
- `Future` 内部状態、trait object、関数ポインタ、旧コード由来 vtable は絶対に持ち越さない。
- 更新は executor drain と state handoff を伴う restart-oriented 方式を既定にする。

## 8. 障害回復

- 通常エラーは `Result`。
- panic はドメイン境界で封じ込める。
- hardware protection の整合性が壊れた場合は縮退運転より fail-closed を優先する。

## 9. セキュリティ

- high-assurance を優先し、移植性と実装単純性を犠牲にする。
- hardware protection は optional ではなく required とする。
- Capability、署名、IOMMU、secure boot、hardware protection を積層し、単一メカニズム依存を避ける。
- WRPKRU-LFENCE tradeoff、cache partitioning、Retpoline / IBRS / STIBP / IBPB などの詳細は [hardware-assisted-security-notes.md](hardware-assisted-security-notes.md) を参照する。
- CPU 要件を満たさない環境はサポート対象外とする。

## 10. 対象ハードウェア

- 対象は限定 SKU の x86_64。
- IOMMU 必須。
- Supervisor 向け保護キー相当の機構がない CPU では採用しない。
- 一般運用の既定案にはしない。

## 関連文書

- [../README.md](../README.md)
- [../design-overview.md](../design-overview.md)
- [variant-a-capability-first.md](variant-a-capability-first.md)
- [hardware-assisted-security-notes.md](hardware-assisted-security-notes.md)
