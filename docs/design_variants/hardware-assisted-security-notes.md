# Hardware-Assisted Security Notes

- Status: Research / future extension note
- Audience: SAS 下の Spectre 緩和、hardware protection、Variant B/C を検討する contributor
- Related: [variant-b-hybrid-hardware-accelerated.md](variant-b-hybrid-hardware-accelerated.md), [variant-c-pks-mandatory.md](variant-c-pks-mandatory.md), [../architecture.md](../architecture.md), [../design-samples/README.md](../design-samples/README.md)

この文書は、旧設計案 9.2 のハードウェア支援セキュリティ詳細を archive から再配置した research note です。
現行 canonical baseline は [../architecture.md](../architecture.md) と
[variant-a-capability-first.md](variant-a-capability-first.md)
を優先し、本書は Variant B/C を補う参考資料として扱います。

## 位置付け

- 本書は hardware-assisted security の詳細受け皿であり、Variant A baseline を更新しない。
- Capability、署名検証、IOMMU、Framework boundary が authority root である点は不変である。
- hardware protection が使えない CPU では Variant A 互換の安全モデルへ戻す。
- Variant C のみ、fallback より fail-closed を優先し得る。

## SAS 下の Spectre threat model

- SAS では全ドメインが同一仮想アドレス空間を共有するため、Spectre 系攻撃の `threat model` は「他ドメインの機密データが同一アドレス空間上に存在する」ことを前提に組み立てる。
- 特に boundary check bypass、secret-dependent memory access、cross-domain metadata 参照は被害半径が大きい。
- 本書で扱う緩和策は、domain boundary ABI や Capability を置き換えるものではなく、microarchitectural leakage の縮小策である。

## WRPKRU-LFENCE tradeoff

- `WRPKRU-LFENCE tradeoff` は、domain transition や secret access で「どこまで hardware protection を優先し、どこだけ barrier を足すか」を決める研究論点である。
- archive 由来の目安では、`WRPKRU` は軽量な権限制御、`LFENCE` は高価だが強い投機停止として整理する。
- 現行 docs では exact cycle cost を normative value にせず、microarchitecture-dependent な reference note とする。
- `LFENCE` は万能策として乱用せず、hardware protection で覆えない経路や暗号処理などに絞る。

## Protection key class strategy

- protection key は domain ID と 1:1 に固定するのではなく、trust level と data sensitivity class に割り当てる研究案として扱う。
- archive 由来の分割案では、低い key 番号側を trust level、高い key 番号側を data sensitivity class に使う。
- この方式は有限個の protection key で多くの domain を論理分離するための reference strategy であり、現行の canonical ABI や authority model には影響しない。
- 設計サンプル:
  [../design-samples/security/mpk_protection_key.rs](../design-samples/security/mpk_protection_key.rs),
  [../design-samples/security/pkru_value.rs](../design-samples/security/pkru_value.rs),
  [../design-samples/security/domain_permissions.rs](../design-samples/security/domain_permissions.rs),
  [../design-samples/security/domain_transition.rs](../design-samples/security/domain_transition.rs)

## 補助緩和策

### 1. cache partitioning / secret placement

- `cache partitioning` は、高価値データと一般データの cache interference を減らす補助策である。
- Intel CAT のような仕組みが使える環境では、secret material や管理構造に専用 cache way を割り当てる研究案を採れる。
- `secret placement` は、機密データを一般データと別 class / 別領域へ寄せ、必要に応じて dedicated storage へ隔離する設計メモである。

### 2. Selective barriers / boundary hardening

- domain boundary での speculation barrier は、unchecked な cross-domain path を塞ぐ補助手段として検討する。
- `LFENCE` の選択基準は、外部入力に基づく分岐直後、hardware protection で覆えない secret access、timing-sensitive cryptographic path を中心にする。
- 設計サンプル:
  [../design-samples/security/lfence_policy.rs](../design-samples/security/lfence_policy.rs)

### 3. Traditional mitigations

- `Retpoline`、`IBRS`、`STIBP`、`IBPB` は、SAS / SPL でも補助 mitigation として併用し得る。
- scheduling randomization は timing-noise 付与の研究案として扱う。
- これらは hardware protection が使えない場合の fallback ではなく、追加で積層する optional mitigation とする。

## 運用メモ

- Variant B では hardware protection が使えない CPU でも Variant A 互換モードで動作できることを前提にする。
- Variant C では hardware protection の欠落や整合性破壊をサポート外または fail-closed 条件として扱う。
- Secure Boot や cell signature / revocation の詳細は loader policy の一部であり、本書へ重複定義しない。

## 旧設計案からの読み替え

| 旧設計案の項目 | 現行の扱い |
| --- | --- |
| 9.2.1 SAS 環境における Spectre の深刻性 | research note |
| 9.2.2.1 MPK / PKU を第一級市民とする設計 | Variant B/C 向け research note |
| 9.2.2.2 LFENCE の選択的使用 | Variant B/C 向け research note |
| 9.2.2 の cache partitioning / secret placement | Variant B/C 向け research note |
| 9.2.3 Retpoline / IBRS / STIBP / IBPB などの基本的緩和策 | optional mitigation note |

## 関連文書

- [variant-b-hybrid-hardware-accelerated.md](variant-b-hybrid-hardware-accelerated.md)
- [variant-c-pks-mandatory.md](variant-c-pks-mandatory.md)
- [../architecture.md](../architecture.md)
- [../design-samples/README.md](../design-samples/README.md)
