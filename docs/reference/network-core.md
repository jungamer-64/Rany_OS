# ExoRust Network Core Reference

- Status: Reference
- Audience: ネットワーク実装、レビュー、性能設計、datapath 整理の前提を確認したい contributor
- Related: [ドキュメントハブ](../README.md), [アーキテクチャ概要](../architecture.md), [API リファレンス](api-reference.md), [性能目標](performance-targets.md), [Kernel Roadmap](../proposals/kernel-roadmap.md)

この文書は、ネットワーク datapath の所有権、非同期処理、性能モデルの contract を定義します。
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
| retained payload | 凍結した共有 payload。どの handle からも書き込めず、最後の handle と device region が返却されるまで内容を保つ | `RetainedPayload` |
| adaptive polling | 低負荷では interrupt、高負荷では polling / hybrid へ切り替えるモデル | `net::datapath::optimization`, runtime device control |
| batch processing | 複数 packet をまとめて処理する最適化 | `PacketBatch`, `BatchProcessor` |
| scatter-gather | multi-buffer DMA / descriptor chaining による送受信 | `PacketPayload` と backing を保持する packet region による driver queue submission |

## 3. Datapath and polling

### 3.1 Normative: PacketRef / PacketPayload を中心に据える

- NIC は事前に確保された packet / DMA buffer へ直接読み書きする。
- protocol 層は `Vec<u8>` への統合を前提にせず、packet-backed payload を運ぶ。
- packet の drop / recycle は pool 回収と結び付け、再利用可能な ownership cycle を維持する。
- `PacketPayload` は常に非空であり、空 segment、総長 overflow、3 segment 以上の storage allocation failure を fallible constructor で区別する。所有権を消費する構築・prepend・split に失敗した場合は input owner を error とともに返す。
- payload 内の変更可能な借用は初期化済み byte に限る。segment window と総長は payload が一体として管理し、headroom への in-place prepend は両者を同時に更新する。失敗時には可視領域・内容・所有権を変更しない。
- packet の backing は最後の window が返却されるまで保持する。分割は可視領域に加えてアクセス可能な領域も分割し、resize・headroom 操作で他の window の範囲へ戻れないようにする。最後の返却は pool への再利用、または未完了の DMA を保持する退役 owner への移譲を行う。
- `PacketRef` が安全に公開するのは初期化済みの可視領域だけとする。`data_capacity`、`headroom`、`tailroom` は別の数量であり、software growth が新たに可視化する byte は初期化してから公開する。
- network TX の正規所有権単位は `PacketPayload` とし、byte-slice への統合を送信の前提にしない。
- 送信後も内容を保持する必要がある payload は `RetainedPayload` に凍結する。凍結した payload は読み取り専用で、複製せずに追加の handle を保持できる。handle の分割は window だけを変える。
- pool の RAM には packet の byte だけを置く。slot の header、参照数、回収先は通常の kernel memory に置き、IOMMU mapping を通して device から到達できないようにする。
- pool は用途ごとに分ける。runtime は frame 用と生成 header 用の slot を持ち、RX buffer は port ごとの pool から供給する。pool は所有者の handle と貸出中の slot がなくなるまで存続する。

### 3.2 Normative: RX DMA authority と TX lease を分離する

- RX posting は `RxBuffer` の空 window から作る、backing を保持した writable region を使う。容量は現在の data origin から末尾までであり、headroom を含めない。device address は port ごとの DMA admission で確立し、packet の属性として保持しない。
- completion は device が書き終えた frame layout を検証して `ReceivedPacket` へ一方向に遷移する。frame length より後ろの tail は初期化済みデータとして公開しない。
- driver の RX lease は投稿前、device 所有中、検証済み完了後を区別する。device 所有中の capsule を破棄しても packet を返却せず、framework の停止 owner が backing を保持する。CPU アクセスと返却には、対応する terminal completion または確認済みの queue 停止が必要となる。
- ABI callback の cookie、instance、code lease は借用中および packet lease の返却完了まで保持する。停止後の返却失敗は同じ未消費 owner で再試行し、消費済みの失敗は再返却しない。
- 送信単位は frame であり、生成した header packet と body からなる。body は所有権を渡す `PacketPayload` か、送信側が自分の handle を持ち続ける `RetainedPayload` である。所有権を渡す body は headroom があれば header をその場に前置する。
- port が frame を受理すると、frame は device から見える region だけになる。所有 packet は region へ消費され、retained body は凍結済みなので、region が存在する間その byte へ書き込める CPU handle は存在しない。region は driver の exactly-once completion か port 停止の成功まで backing を pool へ返さない。送信側へ返却する owner はない。
- 受理の成否が送信側への唯一の結果である。拒否は理由（interface 停止、port 不在、port 停止、lease 枯渇、descriptor 上限超過、lease 記憶域不足）と未変更の frame を返し、device access を一切残さない。
- TX lease は port ごとの表が所有し、`Queued -> Submitting -> DeviceOwned -> 解放` の順序を持つ。submission 中に届いた同期 completion は `Submitting` に記録し、descriptor visit の終了時に適用する。completion はその port 自身の submit 済み lease にだけ有効で、他 port の lease、未 submit の lease、重複 completion は拒否する。
- completion outcome は `Transmitted`、`NotTransmitted`、`OutcomeUnknown` を区別し、port ごとに計数する。port の停止は受理を閉じて未 submit の lease を解放し、driver が device access の終了を証明した後にだけ受理済みの lease を解放する。停止に失敗した port は lease を保持したまま再試行を待つ。
- device が公開する `max_tx_segments` が descriptor fan-out の authority である。TCP は payload の segment 数をこの上限から header 用の 1 を引いた数に収める。上限を超える frame は、先頭の小さな body segment（合計 64 byte まで）を header packet の tailroom へ移して収め、それでも収まらなければ受理しない。
- TX queue を複数持つ port は queue ごとに FIFO と worker を持つ。frame の flow hash が queue を選ぶため、同じ flow の frame と同じ datagram の fragment は submission 順を保つ。
- port の mapping owner は packet window と独立に物理 backing を保持する。TX の mapping は device の読み取りだけを許可し、書き込みを許可するのはその port 自身の RX pool の mapping だけである。mapping は port の停止まで保持するため、device は送信した frame の backing を停止まで読み取れる。backing を保持するものが mapping だけになった場合は、mapping 表が閾値を超えた時点で退役させる。IOTLB の退役完了まで RAM を解放せず、translation の未完了状態は再投稿へ使わない。port の終了は owner を保持して `Busy` を返す。

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
- IPv4 / IPv6 の再構成では、各 fragment が受信 packet を保持する。そのため保持数を datagram あたり 64、reassembler 全体で 512 に制限し、上限を超える fragment はその datagram を破棄する。期限切れの回収は fragment の到着ではなく stack の周期処理で行い、先頭 fragment を受信済みの datagram ごとに Time Exceeded を返す。
- IPv6 は quoted packet、fragment reassembly、TX を含めて scatter-gather / packet-backed ownership で扱う。
- TCP send の成功は send buffer admission の完了を意味する。admission 前の connection、budget、allocation、routing failure は payload owner を error で返し、receive の EOF は空 payload ではなく `EndOfStream` で表す。
- TCP の再送キューは segment を retained payload として ACK まで保持し、送信のたびに同じ backing の handle を渡す。キューに入った segment は sequence 空間を消費済みであり、送信が受理されなかった場合は再送タイマーが再試行する。ACK はキューの handle を直ちに解放し、device が読み取り中の backing は region が completion まで保持する。
- socket の受信キュー（TCP、UDP、RAW）が保持する受信 payload は、segment 数を runtime 全体で 512 までとする。上限を超える payload はキューに入れない。port の RX pool は、IPv4 / IPv6 の再構成、TCP の out-of-order、socket 受信キューの各上限と、device へ投稿しておく予備を合わせた数の buffer を持ち、保持が受信を枯渇させないようにする。
- TCP の challenge ACK と stateless RST の送信予約は kernel 全体の時間窓で制限する。共有実行資源への負荷を抑えるため、system uptime を基準に期間更新と予約を直列化し、packet の構築・送信拒否後も予約を消費済みとして扱う。
- 各 TCB の out-of-order queue は最大 16 segment とし、runtime 全体では 512 permit を admission 前に予約する。overlap、eviction、prune、connection close の全経路が permit を返す。
- 送信窓 (SND.WND) は RFC 5961 の ACK 検証を通過したセグメントだけが、SND.WL1 / SND.WL2 より古くない場合に更新する。TS.Recent と SACK scoreboard も同じ検証の後で更新し、fast path も slow path と同じ timestamp admission を通す。
- 広告する受信窓は、合意した window scale でシフトしてから 16 bit に clamp する。SYN cookie から確立した接続は scale / SACK / timestamp を復元できないため、stateless な SYN-ACK ではこれらを提示しない。
- passive open で確立した接続は listener の accept queue に受理された時点で接続用の socket id を得る。受理できない場合は RST で中止し、所有者のいない ESTABLISHED TCB を残さない。
- FIN は close 要求後、送信バッファの全データを再送キューへ渡した後にだけ送り、データと同様に ACK されるまで再送する。
- TCP 接続 socket の終了処理を行う所有者は常に一つである。`close` はハンドルを消費して終了処理を runtime へ移し、runtime は TCB が終わった時点で socket を unregister する。close せずにハンドルを破棄することは RFC 9293 の ABORT であり、SYN-RECEIVED、ESTABLISHED、FIN-WAIT-1/2、CLOSE-WAIT では `<SEQ=SND.NXT><CTL=RST>` を送り、TCB と socket を同時に解放する。handshake 中の接続に対する `close` も ABORT とする。listener の解放は、accept queue に残る接続と未確立の接続を ABORT する。
- TCB の終了（LAST-ACK での FIN の ACK、TIME-WAIT / FIN-WAIT-2 / SYN-RECEIVED の期限切れ、RST の受理、再送の打ち切り）は、TCB をテーブルから取り除いた経路だけが処理する。その経路が再送キューを解放し、close 済みの socket は unregister する。ハンドルが保持している socket には閉じた状態と refused / reset / timeout の区別を記録し、ハンドルの解放時に unregister する。
- core canonical docs は packet / endpoint / ownership vocabulary を前提に語彙を組み立てる。

### 4.3 Validation boundary

- ownership state、RX frame publication、TCP reassembly/retransmit、driver completion は unit / integration test で検証する。
- ホスト側では CPU のみで成立する protocol logic を検証し、packet-backed ingress は network full-boot profile の実行資源で検証する。
- QEMU の VirtIO case は RX posting、TX used-ring completion、buffer recycle を含む integration boundary であり、実 NIC throughput の証拠ではない。
- `>= 10Gbps` は実 NIC と明示した workload で測定するまで達成済みと扱わない。

## 5. Reading guide

- 広域の公開 API 形状は [api-reference.md](api-reference.md) を参照する。
- 性能 gate と測定基準は [performance-targets.md](performance-targets.md) を参照する。
- 実装順序と real NIC / offload workstream は [../proposals/kernel-roadmap.md](../proposals/kernel-roadmap.md) を参照する。
