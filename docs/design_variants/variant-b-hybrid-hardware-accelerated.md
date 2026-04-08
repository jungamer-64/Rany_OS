# Variant B: Hybrid Hardware-Assisted Isolation

- Status: Research / future extension
- Audience: ハードウェア支援分離を検討する contributor
- Related: [ドキュメントハブ](../README.md), [設計ハブ](../design-hub.md), [Variant A](variant-a-capability-first.md), [Hardware-Assisted Security Notes](hardware-assisted-security-notes.md)

Variant A を土台にしつつ、対応 CPU では PKS/MPK 系を追加防御として使う案です。未対応 CPU では Variant A と同じ安全モデルで動作できることを必須条件にします。

| 項目 | 方針 |
|------|------|
| authority の根 | Capability、署名検証、ローダー方針、IOMMU。ハードウェア支援は補助 |
| 必要 CPU / HW | x86_64、IOMMU 必須。PKS/MPK は利用可能なら有効化 |
| live update をまたげるもの | `#[repr(C)]` 状態、handle、token、バージョン付きシリアライズ状態 |
| 位置付け | 研究・将来拡張 |

## 1. SAS/SPL の前提

- SAS/SPL は Variant A と同じく維持する。
- 直接呼び出しは高速化の手段であり、authority の根ではない。
- ハードウェア支援の有無で公開 API や安全モデルを変えない。

## 2. 権限モデル

- authority の根は引き続き Capability に置く。
- ハードウェア支援の有無に関わらず、危険 API は Capability を必須にする。
- PKS/MPK は権限検査を置き換えるものではなく、被害半径縮小のための追加レイヤーとする。

## 3. ドメイン境界 ABI

- 境界 ABI は Variant A と同じく `#[repr(C)]`、opaque handle、token、固定 ABI の状態に限定する。
- ハードウェア支援は ABI の不安定性を解決しないため、`dyn Trait` や `#[repr(Rust)]` を境界に持ち込まない。

## 4. unsafe / Framework 境界

- `unsafe` は Framework と低レベル HAL に集約する。
- PKS/MPK 操作は Framework 内の限定モジュールに閉じ込める。
- higher layer から protection key の直接操作を許さない。

## 5. Async / プリエンプション方針

- ISR から deferred wake する原則は維持する。
- APIC タイマーによる強制プリエンプションを既定にする。
- ハードウェア支援の有無で executor の進行保証を変えない。

## 6. メモリ / DMA

- Exchange Heap、`RRef`、IOMMU 必須は Variant A と同じ。
- 機密度が高いバッファやメタデータに対して、対応 CPU では protection key や cache partitioning を追加する。
- ただし、DMA 制御の主軸は常に IOMMU と Capability に置く。

## 7. ライブアップデート

- 持ち越し可能 / 禁止のルールは Variant A と同じ。
- protection key を使う場合でも、旧コード由来の vtable、`Future` 状態、関数ポインタは持ち越さない。
- ハードウェア支援状態は export/import 対象ではなく、切替後に再設定する。

## 8. 障害回復

- 通常エラーは `Result` ベース、panic は封じ込める。
- ハードウェア支援の設定失敗は capability downgrade または fallback を返す。
- fallback が成立しない場合のみ該当機能を無効化する。

## 9. セキュリティ

- Capability、署名、IOMMU が基礎レイヤー。
- 対応 CPU では PKS/MPK を使って、高価値データや管理構造へのアクセスを絞る。
- LFENCE、cache partitioning、secret placement は選択的に使う。
- WRPKRU-LFENCE tradeoff、protection key class strategy、補助 mitigations の詳細は [hardware-assisted-security-notes.md](hardware-assisted-security-notes.md) を参照する。
- `docs/exorust_design/security/` の擬似コードは主にこの案の説明に対応する。

## 10. 対象ハードウェア

- x86_64 が主対象。
- IOMMU は必須。
- PKS/MPK を提供する CPU では追加防御を有効化し、未対応 CPU では Variant A 互換モードで動作する。

## 関連文書

- [../README.md](../README.md)
- [../design-hub.md](../design-hub.md)
- [variant-a-capability-first.md](variant-a-capability-first.md)
- [hardware-assisted-security-notes.md](hardware-assisted-security-notes.md)
