# ExoRust Network Core Reference

- Status: Reference
- Audience: ネットワーク実装、レビュー、性能設計、datapath 整理の前提を確認したい contributor
- Related: [ドキュメントハブ](../README.md), [アーキテクチャ概要](../architecture.md), [API リファレンス](api-reference.md), [性能目標](performance-targets.md), [Kernel Roadmap](../proposals/kernel-roadmap.md)

この文書は、旧設計案 `rust-kernel-design-proposal.md` の 6.1 / 6.2 で定義していた
ネットワーク原則を、現行 `docs/` 配下の Reference として再配置したものです。
ExoRust のネットワークについて語彙・優先順位・性能モデルを確認したい場合は、
まず本書を参照してください。

## 規範レベルの読み分け

優先順位は次の通りです。

1. `architecture.md`（正本）
2. Accepted ADR
3. `kernel-development-guidelines.md`
4. 本書（Network Core Reference）
5. `api-reference.md`（広域 API 整理）

表記ルール:

- `Normative`: 現行 baseline で守るべき制約
- `Canonical target`: 採択済みだが段階実装中の目標
- `implementation pending`: 目標として採択済みだが、現実装との差分が残る項目
- `Guidance`: 実装整理・補助説明

## 1. Core model

### 1.1 Normative: POSIX socket は正規面にしない

- `socket()` / `bind()` / `listen()` をネットワーク設計の中心に置かない。
- 型付き endpoint、packet-backed payload、queue submission、capability 検証を優先する。
- network API の評価軸は packet ownership / payload handoff / queue submission に置く。

### 1.2 Normative: ネットワークは ownership-based datapath として扱う

- パケット受信後の主語は「バイト列」ではなく packet-backed payload である。
- バッファの移動単位は packet pool / `PacketRef` / `PacketPayload` を中心に整理する。
- `RAW endpoint`、TCP、UDP、reassembly、retransmit の全経路で「誰が payload を所有しているか」を設計の主軸に置く。

### 1.3 Canonical target: TCP でも zero-copy fast path を第一級に扱う

- TCP でも core の性能モデルは packet-backed payload handoff を優先する。
- datapath の正規面は ownership / payload / queue に置く。
- end-to-end zero-copy が達成できていない経路は `implementation pending` として扱い、copy path を canonical baseline とみなさない。

## 2. Core vocabulary

| 用語 | 本書での意味 | 現行 tree での主な着地点 |
| --- | --- | --- |
| mempool / packet pool | NIC DMA と packet 再利用のための固定長バッファプール | `net::datapath::mempool`, `PacketPool` |
| packet-backed payload | packet ownership を保った送受信単位 | `PacketRef`, `PacketPayload` |
| ownership-based buffering | queue / endpoint / protocol 層が payload 所有権を明示して受け渡す設計 | `net::l4::endpoint`, `net::datapath`, `kernel_api::resource::net` |
| end-to-end zero-copy | driver -> protocol -> app まで flatten / copy を最小化する経路 | `Canonical target` |
| adaptive polling | 低負荷では interrupt、高負荷では polling / hybrid へ切り替えるモデル | `net::datapath::adaptive_polling`, runtime device control |
| batch processing | 複数 packet をまとめて処理する最適化 | `PacketBatch`, `BatchProcessor` |
| scatter-gather | multi-buffer DMA / descriptor chaining による送受信 | datapath / driver queue submission |

## 3. Datapath and polling

### 3.1 Normative: packet pool を中心に据える

- NIC は事前に確保された packet pool / DMA buffer へ直接読み書きする。
- protocol 層は `Vec<u8>` flatten を前提にせず、packet-backed payload を運ぶ。
- packet の drop / recycle は pool 回収と結び付け、再利用可能な ownership cycle を維持する。

### 3.2 Normative: adaptive polling は baseline の一部

- 低トラフィック時は interrupt-driven を使い、省電力と簡潔な待機を維持する。
- 高トラフィック時は hybrid / busy polling に移行し、receive livelock と interrupt overhead を抑える。
- polling / interrupt 切替は datapath や driver 層の追加オプションではなく、network runtime の標準的な振る舞いとして扱う。

### 3.3 Canonical target: batch / scatter-gather / offload を packet-native に統合する

- batch processing は packet queue / endpoint / driver submission と整合した形で設計する。
- scatter-gather は「複数 buffer を flatten してから送る」前処理ではなく、descriptor chaining を含む native submission として扱う。
- checksum / segmentation / RSS / offload は packet ownership と矛盾しない形で組み込む。

## 4. Endpoint model

### 4.1 RAW endpoint

- `RAW endpoint` は packet-native surface の代表であり、packet ownership exchange を明示的に露出する。
- capability 境界、driver bring-up、diagnostics、datapath 検証の基準面は RAW / packet-native path に置く。

### 4.2 TCP / UDP

- TCP は connection semantics を持つが、core では packet-backed payload queue と endpoint-owned state を中心に扱う。
- UDP は token-aware bind、packet-native receive / send、scope-aware endpoint を優先する。
- core canonical docs は packet / endpoint / ownership vocabulary を前提に語彙を組み立てる。

### 4.3 implementation pending

次の項目は採択済みだが、現実装との乖離が残り得る。

- TCP の全経路で packet-backed payload を end-to-end で維持すること
- reassembly / retransmit / diagnostics まで含めた zero-copy ownership model の全面統一
- driver/runtime/public surface での語彙統一（packet pool / payload / endpoint / batch / scope）

## 5. Reading guide

- 広域の公開 API 形状は [api-reference.md](api-reference.md) を参照する。
- 性能 gate と測定基準は [performance-targets.md](performance-targets.md) を参照する。
- 実装順序と real NIC / offload workstream は [../proposals/kernel-roadmap.md](../proposals/kernel-roadmap.md) を参照する。
- 旧設計案本文の背景説明は引き続き archive に残すが、現行の network 語彙は本書を正とする。
