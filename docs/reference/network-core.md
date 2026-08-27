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
- end-to-end zero-copy が達成できていない経路は `implementation pending` として扱い、packet-native ownership を canonical baseline にする。

## 2. Core vocabulary

| 用語 | 本書での意味 | 現行 tree での主な着地点 |
| --- | --- | --- |
| mempool / packet allocation | NIC DMA と packet 再利用のための固定長バッファ供給 | `net::datapath::mempool`, `PacketRef`, `PacketPayload` |
| packet-backed payload | packet ownership を保った送受信単位 | `PacketRef`, `PacketPayload` |
| ownership-based buffering | queue / endpoint / protocol 層が payload 所有権を明示して受け渡す設計 | `net::l4::endpoint`, `net::datapath`, `kernel_api::resource::net` |
| end-to-end zero-copy | driver -> protocol -> app まで packet ownership を維持する経路 | `Canonical target` |
| adaptive polling | 低負荷では interrupt、高負荷では polling / hybrid へ切り替えるモデル | `net::datapath::adaptive_polling`, runtime device control |
| batch processing | 複数 packet をまとめて処理する最適化 | `PacketBatch`, `BatchProcessor` |
| scatter-gather | multi-buffer DMA / descriptor chaining による送受信 | `PacketPayload` / `NetTxSegment` による driver queue submission |

## 3. Datapath and polling

### 3.1 Normative: PacketRef / PacketPayload を中心に据える

- NIC は事前に確保された packet / DMA buffer へ直接読み書きする。
- protocol 層は `Vec<u8>` への統合を前提にせず、packet-backed payload を運ぶ。
- packet の drop / recycle は pool 回収と結び付け、再利用可能な ownership cycle を維持する。
- `PacketPayload` は常に非空であり、空 segment、総長 overflow、3 segment 以上の storage allocation failure を fallible constructor で区別する。所有権を消費する構築・prepend・split に失敗した場合は input owner を error とともに返す。
- payload 内の変更可能な借用は初期化済み byte に限る。segment window と総長は payload が一体として管理し、headroom への in-place prepend は両者を同時に更新する。失敗時には可視領域・内容・所有権を変更しない。
- `PacketRef` が安全に公開するのは初期化済みの可視領域だけとする。`data_capacity`、`headroom`、`tailroom` は別の数量であり、software growth が新たに可視化する byte は初期化してから公開する。
- network TX の正規所有権単位は `PacketPayload` であり、旧 `datapath::zero_copy`
  facade や byte-slice TX surface を再導入しない。

### 3.2 Normative: RX DMA authority と TX lease を分離する

- RX posting は `RxBuffer` が持つ `RxWritableRegion { cpu_ptr, device_addr, writable_len }` だけを driver へ委譲する。`writable_len` は backing の現在の data origin から末尾までであり、headroom を含めない。
- completion は device が書き終えた frame layout を検証して `ReceivedPacket` へ一方向に遷移する。frame length より後ろの tail は初期化済みデータとして公開しない。
- TX queue の受理は DMA read authority の取得を意味し、driver は buffer を参照しなくなった後に exactly-once completion を返す。拒否は buffer を一切保持していないことを意味する。
- TX lease は `Queued -> Submitting -> DeviceOwned -> Released(outcome)` の順序を持つ。同期 completion、重複 completion、reset を同じ state transition で扱い、caller 向け送信通知と DMA lease の解放を同一視しない。
- completion outcome は `Transmitted`、`NotTransmitted`、`OutcomeUnknown` を区別する。stop/reset で DMA authority の安全な失効を証明できない owner は再利用せず quarantine する。
- device が公開する `max_tx_segments` が descriptor fan-out の authority である。TCP/IP はこの上限へ分割し、分割不能な RAW frame は未消費の payload owner を typed error で返す。

### 3.3 Normative: adaptive polling は baseline の一部

- 低トラフィック時は interrupt-driven を使い、省電力と簡潔な待機を維持する。
- 高トラフィック時は hybrid / busy polling に移行し、receive livelock と interrupt overhead を抑える。
- polling / interrupt 切替は datapath や driver 層の追加オプションではなく、network runtime の標準的な振る舞いとして扱う。

### 3.4 Canonical target: batch / scatter-gather / offload を packet-native に統合する

- batch processing は packet queue / endpoint / driver submission と整合した形で設計する。
- scatter-gather は「複数 buffer を単一 owner に畳んでから送る」前処理ではなく、descriptor chaining を含む native submission として扱う。
- checksum / segmentation / RSS / offload は packet ownership と矛盾しない形で組み込む。

## 4. Endpoint model

### 4.1 RAW endpoint

- `RAW endpoint` は packet-native surface の代表であり、packet ownership exchange を明示的に露出する。
- capability 境界、driver bring-up、diagnostics、datapath 検証の基準面は RAW / packet-native path に置く。

### 4.2 TCP / UDP

- TCP は connection semantics を持つが、core では packet-backed payload queue と endpoint-owned state を中心に扱う。
- UDP は token-aware bind、packet-native receive / send、scope-aware endpoint を優先する。
- DNS は parser / cache / record data まで packet-backed view を正規面とし、`String` / raw byte ownership への早期変換を baseline にしない。
- DNS 応答の canonical ownership は `DnsResponseView { payload, records }` に置き、cache も response payload ownership + record metadata を保持する。
- IPv4 は timeout / unknown-protocol / reassembled packet を含めて packet-backed quoted/original payload で扱う。
- IPv6 は quoted packet、fragment reassembly、TX を含めて scatter-gather / packet-backed ownership で扱う。
- runtime / device / driver の TX 境界は `PacketRef` 単体ではなく `PacketPayload` を正規送信単位として扱う。
- TCP send の成功は send buffer admission の完了を意味する。admission 前の connection、budget、allocation、routing failure は payload owner を error で返し、receive の EOF は空 payload ではなく `EndOfStream` で表す。
- TCP retransmit は同じ packet backing を `Ready` / `InFlight` 間で移動する。ACK が DMA completion より先に到着しても completion までは owner を保持し、未送信または outcome 不明の completion は再送可能な ownership へ戻す。
- 各 TCB の out-of-order queue は最大 16 segment とし、runtime 全体では 512 permit を admission 前に予約する。overlap、eviction、prune、connection close の全経路が permit を返す。
- core canonical docs は packet / endpoint / ownership vocabulary を前提に語彙を組み立てる。

### 4.3 Validation boundary

- ownership state、RX frame publication、TCP reassembly/retransmit、driver completion は unit / integration test で検証する。
- QEMU の VirtIO case は RX posting、TX used-ring completion、buffer recycle を含む integration boundary であり、実 NIC throughput の証拠ではない。
- `>= 10Gbps` は実 NIC と明示した workload で測定するまで達成済みと扱わない。

## 5. Reading guide

- 広域の公開 API 形状は [api-reference.md](api-reference.md) を参照する。
- 性能 gate と測定基準は [performance-targets.md](performance-targets.md) を参照する。
- 実装順序と real NIC / offload workstream は [../proposals/kernel-roadmap.md](../proposals/kernel-roadmap.md) を参照する。
- 旧設計案本文の背景説明は引き続き archive に残すが、現行の network 語彙は本書を正とする。
