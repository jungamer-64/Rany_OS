# **次世代高性能x86\_64 Rustカーネルアーキテクチャ：Linux/POSIX互換を排除した極限効率の追求**

## **1\. 序論：レガシーからの脱却とRustによるOS設計のパラダイムシフト**

### **1.1 現行OSアーキテクチャの限界とボトルネック**

現代のオペレーティングシステム（OS）、特にLinuxやWindowsは、1970年代に確立された設計原則の上に成り立っています。これらのシステムは、C言語やC++といったメモリ安全性を保証しない言語で記述されているため、システムの安定性とセキュリティを確保するために、ハードウェアによる強力な分離機構に依存してきました。具体的には、x86アーキテクチャにおけるリングプロテクション（Ring 0とRing 3の分離）と、MMU（Memory Management Unit）による仮想アドレス空間の分離です 1。

しかし、ハードウェアの進化、特に100Gbpsを超えるネットワークインターフェースやマイクロ秒単位のレイテンシを持つNVMeストレージの登場により、これらの分離メカニズム自体が無視できないパフォーマンスのボトルネックとなっています。

* **コンテキストスイッチのオーバーヘッド:** プロセス間の切り替えには、CR3レジスタの書き換えによる仮想アドレス空間のスイッチが必要です。これに伴いTLB（Translation Lookaside Buffer）のフラッシュが発生し（PCID機能で軽減されるとはいえ）、後続のメモリアクセスでキャッシュミスを誘発します。研究によると、Linuxにおけるコンテキストスイッチのコストは数マイクロ秒に達する場合があり、これは現代の高速デバイスの処理時間と同等のオーダーです 4。  
* **システムコールのコスト:** ユーザー空間とカーネル空間の境界を跨ぐシステムコール（SYSCALL/SYSRET）は、単なる関数呼び出しではなく、特権レベルの遷移、スタックの切り替え、レジスタの退避・復帰を伴います。SPECTREやMELTDOWNといったCPUの脆弱性に対する緩和策（KPTIなど）は、このオーバーヘッドをさらに増大させました 7。  
* **データコピーの不可避性:** 異なる保護ドメイン（カーネルとユーザー）間でデータを受け渡す際、安全性のためにデータのコピーが必要となる場面が多々あります。mmapやMSG\_ZEROCOPYなどの最適化手法は存在しますが、アライメント制約やページフォールの処理など、複雑な管理コストを伴います 9。

### **1.2 Rustがもたらす「言語ベース分離」の可能性**

Rustプログラミング言語の登場は、システムプログラミングに革命をもたらしました。Rustのアフィン型システム（Affine Type System）と所有権（Ownership）モデルは、ガベージコレクション（GC）なしでコンパイル時にメモリ安全性を保証します 11。この特性は、OS設計における根本的な前提を覆します。

もしコンパイラが「あるコード領域が、所有権を持たないメモリには絶対にアクセスしない」ことを数学的に証明できるならば、実行時にハードウェア（MMU）を用いてアクセス違反を監視する必要はなくなります。これを\*\*言語内分離（Intralingual Isolation）\*\*と呼びます 13。

### **1.3 本提案の核心：ExoRustアーキテクチャ**

本レポートでは、Linux/POSIX互換性を完全に排除し、Rustの特性を極限まで活かした新しいx86\_64用カーネルアーキテクチャ「ExoRust（仮称）」を提案します。このアーキテクチャは、以下の3つの柱に基づいています。

1. **単一アドレス空間 (Single Address Space: SAS):** 全てのアプリケーション、ドライバ、カーネルコアを同一の仮想アドレス空間で実行し、TLBフラッシュを排除する 15。  
2. **単一特権レベル (Single Privilege Level: SPL):** 全てのコードをRing 0で実行し、システムコールを通常の関数呼び出し（Function Call）に置き換える 17。  
3. **非同期中心主義 (Async-First):** カーネルスレッドによるプリエンプティブなマルチタスクを廃止し、RustのFutureとasync/awaitを用いた協調的マルチタスクを採用する 18。

本稿では、Theseus OS 14、RedLeaf 13、Asterinas 20 といった先行研究の知見を統合し、実用化に向けた具体的な設計案を提示します。

---

## **2\. アーキテクチャ概論：単一アドレス空間 (SAS) と単一特権レベル (SPL)**

従来のOSが「プロセス」という単位でリソースとアドレス空間を隔離していたのに対し、ExoRustは「セル（Cell）」または「ドメイン（Domain）」と呼ばれる言語レベルのモジュール単位でシステムを構成します。

### **2.1 単一アドレス空間 (SAS) のメカニズムと利点**

ExoRustでは、システム上の全てのエンティティが単一の64ビット仮想アドレス空間を共有します。

* **ポインタの普遍性:** あるドメイン（例：ネットワークドライバ）で生成されたデータ構造へのポインタは、システム内の他のあらゆるドメイン（例：Webサーバーアプリケーション）においても有効です。アドレス変換やシリアライゼーションを経ることなく、ポインタを渡すだけでデータの所有権を移動（Move）できます。これは真のゼロコピー通信を実現します 16。  
* **TLB効率の最大化:** プロセス切り替えに伴うCR3レジスタの書き換えが発生しないため、TLBエントリは常に有効な状態を保ちます。大規模なメモリアクセスを伴うワークロードにおいて、TLBミスの削減は劇的なパフォーマンス向上に寄与します 6。  
* **永続性と共有:** アドレス空間が永続的であるため、メモリ上のデータ構造をファイルシステムのように扱うことも論理的に可能です。従来の「ファイルを開く \-\> バッファに読み込む」という手順は、「データ構造へのポインタを取得する」という操作に置き換わります 16。

### **2.2 単一特権レベル (SPL) によるオーバーヘッドの排除**

ExoRustは、全てのコードをx86\_64のスーパーバイザーモード（Ring 0）で実行します。

* **システムコールの関数化:** アプリケーションがディスクへの書き込みを要求する場合、Linuxではwrite()システムコールを発行し、CPUモードの切り替えが発生します。ExoRustでは、これは単なる関数呼び出し（storage\_driver::write()）となります。関数呼び出しのコストは数ナノ秒（CPUサイクル数で言えばCALL/RET命令のみ）であり、システムコールの数百ナノ秒〜数マイクロ秒と比較して桁違いに高速です 7。  
* **特権命令の管理:** 全てのコードがRing 0にあるため、理論上は任意のコードがCLI（割り込み禁止）などの危険な命令を実行可能です。これを防ぐため、Rustコンパイラとローダーがゲートキーパーとなります。アプリケーションコード（Safe Rust）にはunsafeブロックの使用を禁止し、特権命令を含む操作は、検証済みの「OSフレームワーク」モジュールのみに許可します 20。

### **2.3 アーキテクチャの比較**

| 特徴 | Linux (モノリシック/標準) | マイクロカーネル (L4, Minix) | ExoRust (提案: SAS/SPL) | 効率への影響 |
| :---- | :---- | :---- | :---- | :---- |
| **アドレス空間** | プロセスごとに分離 | サーバーごとに分離 | **単一 (SAS)** | TLBフラッシュ排除、キャッシュ効率最大化 |
| **特権レベル** | カーネル(Ring0) / ユーザー(Ring3) | カーネル(Ring0) / ユーザー(Ring3) | **全てRing 0 (SPL)** | モードスイッチ排除、システムコールオーバーヘッド消滅 |
| **分離メカニズム** | ハードウェア (MMU) | ハードウェア (MMU) \+ IPC | **ソフトウェア (コンパイラ/型)** | 実行時チェック不要、ビルド時検証へのシフト |
| **通信コスト** | データコピー (copy\_to\_user) | IPC (メッセージパッシング) | **関数呼び出し / ゼロコピー** | メモリ帯域幅の節約、レイテンシの最小化 |
| **安全性** | 実行時例外 (Segfault) | 実行時例外 (サービス再起動) | **コンパイルエラー / パニック** | バグの早期発見、実行時クラッシュの局所化 |

---

## **3\. Rust言語による「言語内分離 (Intralingual Isolation)」の実装**

ハードウェアによる分離を捨てた場合、システムの安全性はRustの型システムとコンパイラによる静的解析、および実行時の動的リンク機構によって担保されます。

### **3.1 「セル (Cell)」モデルによるモジュール化**

Theseus OSが提唱する「セル」という概念を採用します 14。

* **定義:** セルは、Rustのクレート（Crate）に相当するソフトウェアの構成単位です。各セルは単一のオブジェクトファイル（ELFなど）としてコンパイルされます。  
* **動的リンク:** カーネルは起動時、あるいは実行中に必要に応じてセルをロードします。カスタムリンカーがシンボル解決を行い、メモリ上に配置します。この際、従来のOSのような「未解決シンボル」を許容せず、ロード時に全ての依存関係が型レベルで整合していることを検証します。  
* **不変性:** 一度ロードされたセルのコードセクションは読み取り専用（W^X: Write XOR Execute）としてマークされ、実行中の改変を防ぎます。

### **3.2 unsafeコードの封じ込めとTCBの最小化**

Rustの安全性保証はunsafeブロック内では無効化されます。したがって、システム全体の安全性は「いかにunsafeコードを減らし、隔離するか」にかかっています。Asterinasプロジェクトが提唱する「Framekernel」アーキテクチャを導入します 20。

* **OSフレームワーク (The Framework):** メモリ割り当て、デバイスレジスタ操作、コンテキストスイッチの最下層など、ハードウェアに直接触れる部分はunsafeを使用せざるを得ません。これらを最小限の「OSフレームワーク」として集約し、厳密な監査と検証を行います。Asterinasの事例では、TCB（Trusted Computing Base）はコードベース全体の約14%に抑えられています 27。  
* **OSサービス:** ファイルシステム、ネットワークスタック、高レベルドライバなどは、フレームワークが提供するSafe APIのみを使用して記述します。これにより、これらのサービスにバグがあっても、メモリ安全性（Use-after-freeなど）は侵害されないことが保証されます。

### **3.3 コンパイラ署名とロード時検証**

悪意のある、あるいはバグを含むバイナリがロードされるのを防ぐため、ExoRustは「証明付きコード (Proof-Carrying Code)」の概念を簡易化して適用します 15。

1. **コンパイル時:** 信頼されたビルドサーバー上のRustコンパイラが、ソースコードを検証し、バイナリを生成します。この際、コンパイラは「このバイナリはSafe Rustのみで記述されている（あるいは許可されたunsafeパターンのみを含む）」という暗号学的署名を付与します。  
2. **ロード時:** カーネルのローダーは、バイナリの署名を検証します。署名が有効であれば、そのバイナリがメモリ安全性のルールを遵守していると見なし、Ring 0での実行を許可します。これにより、実行時のオーバーヘッドなしに安全性を担保できます。

---

## **4\. カーネル並行性モデル：Async/Awaitによる協調的マルチタスキング**

Linuxのような1:1スレッドモデル（カーネルスレッド）は、高並列I/O処理においてコンテキストスイッチのオーバーヘッドが大きく、スケーラビリティの限界となります。ExoRustは、Rustのasync/await機能をカーネルの基盤となる並行性モデルとして採用します 19。

### **4.1 協調的マルチタスクとExecutor**

ExoRustでは、「プロセス」や「スレッド」の代わりに「タスク（Task）」が実行単位となります。タスクはRustのFutureトレイトを実装したステートマシンです。

* **Executorの役割:** 各CPUコアには、独立したExecutor（実行機）が配置されます。Executorは、登録されたタスク（Future）をポーリング（poll）します。  
* **コンテキストスイッチの軽量化:** タスクがI/O待ち（Poll::Pending）になると、Executorは即座に次のタスクのポーリングに移行します。この切り替えは、スタックの退避・復帰を伴うOSレベルのコンテキストスイッチではなく、単なる関数ポインタの切り替え（ステートマシンの遷移）であるため、コストは極小です 19。  
* **スタックレスコルーチン:** RustのFutureはスタックレスコルーチンとして実装されるため、各タスクに固定サイズの大きなスタックを割り当てる必要がありません。これにより、数万〜数十万の同時接続を少ないメモリフットプリントで処理することが可能になります 31。

### **4.2 割り込みとWakerのブリッジ (Interrupt-Waker Bridge)**

no\_std環境（OSカーネル）で非同期ランタイムを動かす際の最大の課題は、ハードウェア割り込みとFutureの連携です。以下のパターンでこれを解決します 32。

1. **Wakerの登録:** デバイスドライバが非同期操作（例：パケット受信待ち）を開始すると、そのタスクのWakerを作成し、ドライバ共有の構造体（例：割り込みハンドラから参照可能なグローバルなAtomicWakerやロックフリーキュー）に登録します。  
2. **割り込み発生:** ハードウェアからの割り込みが発生すると、CPUは直ちに割り込みサービスルーチン（ISR）を実行します。  
3. **Wakeの発行:** ISRはデバイスのステータスを確認し、対応するWakerのwake()メソッドを呼び出します。これにより、Executorに対して「このタスクは実行可能状態になった」ことが通知されます。  
4. **プリエンプションの回避:** 重要な点として、ISR内では重い処理を行いません。単にタスクをReady状態にするだけです。実際のデータ処理は、ISR終了後にExecutorが再開した際に、通常のタスクとして実行されます。これにより、割り込み禁止時間を最小限に抑えます。

### **4.3 マルチコアスケーリングとShare-Nothingアーキテクチャ**

ロック競合は並列処理の最大の敵です。ExoRustは、SeastarやGlommioといった高性能ユーザー空間フレームワークに見られる「Share-Nothing（シェアード・ナッシング）」アーキテクチャを採用します 35。

* **コアごとの独立性:** 各CPUコアは専用のメモリアロケータ、Executor、およびI/Oキューを持ちます。  
* **メッセージパッシング:** コア間でのデータ共有（Arc\<Mutex\<T\>\>など）は極力避け、コア間通信が必要な場合は、ロックフリーなリングバッファを用いたメッセージパッシングを行います。  
* **ワークスティーリング:** 負荷の偏りを防ぐため、あるコアがアイドル状態になった場合、他のコアのタスクキューからタスクを「盗む（Work Stealing）」機能を実装しますが、これも所有権の移動を伴う安全なプロトコル上で行われます。

### **4.4 スターベーション対策**

協調的マルチタスクの弱点は、あるタスクがCPUを独占して無限ループや長時間計算を行うと、他のタスクが実行されない（スターベーション）ことです。

* **コンパイラによるYieldポイント挿入:** コンパイラプラグインやMIR（Mid-level Intermediate Representation）の解析により、ループのバックエッジや長い関数呼び出しの合間に自動的にyieldポイント（Executorへの制御返却）を挿入する手法が検討されています 30。  
* **ハードウェアタイマーによる強制介入:** 安全策として、APICタイマー割り込みを利用し、一定時間以上Executorに制御が戻らない場合は強制的に現在のタスクを中断させ、Executorを再スケジュールする「協調的とプリエンプティブのハイブリッド」アプローチを採用します 31。

---

## **5\. メモリ管理戦略：静的検証と動的再利用**

Linux互換性を捨てることで、ページングや仮想メモリ管理の複雑さを大幅に削減し、物理メモリの利用効率を最大化します。

### **5.1 物理メモリマッピングと1GB Huge Page**

ExoRustでは、物理メモリ全体を仮想アドレス空間の特定領域（例：0xffff\_8000\_0000\_0000〜）にリニアマッピングします。

* **1GBページの活用:** 可能な限り1GBのHuge Page（PDPTエントリ）を使用してマッピングを行います。これにより、テラバイト級のメモリを持つサーバーであっても、TLBエントリの消費を最小限に抑えられます。4KBページの粒度でマッピングする場合と比較して、TLBミスによるストールをほぼ根絶できます 24。  
* **静的アドレス変換:** 仮想アドレスから物理アドレスへの変換は、単なるオフセットの加算（phys \= virt \- OFFSET）となり、ページテーブルウォークを伴わない高速な変換が可能です。

### **5.2 階層型アロケータ設計**

断片化を防ぎつつ高速な割り当てを実現するため、3層構造のアロケータを実装します。

| 階層 | コンポーネント | 役割 | 実装戦略 |
| :---- | :---- | :---- | :---- |
| **Tier 1** | **Frame Allocator** | 4KiB/2MiB/1GiB単位の物理フレーム管理 | ビットマップ管理。頻繁には呼ばれない。 |
| **Tier 2** | **Global Heap** | 汎用的な動的メモリ割り当て | buddy\_system\_allocator または slab アロケータ。 |
| **Tier 3** | **Per-Core Cache** | コアローカルな高速割り当て | 各コア専用のSlabキャッシュ（LinuxのSLUBに類似）。ロックフリーで動作し、キャッシュラインの競合（False Sharing）を防ぐ。 |

### **5.3 線形型（Linear Types）と交換ヒープ（Exchange Heap）**

RedLeaf OSで提唱された「交換ヒープ」の概念を取り入れ、ドメイン間の完全な分離とゼロコピー通信を両立させます 40。

* **プライベートヒープ:** 各ドメイン（セル）は専用のプライベートヒープを持ちます。ここのオブジェクトはドメイン外からは参照できません。  
* **交換ヒープ:** ドメイン間で共有・移動するオブジェクトは「交換ヒープ」に割り当てられます。これらはRRef\<T\>（Remote Reference）のようなラッパー型を通じて管理されます。  
* **所有権の移動と分離:** あるドメインがRRef\<T\>を別のドメインに渡すと、Rustのムーブセマンティクスにより、送信元はアクセス権を失います。これにより、「共有されているが、所有者は常に一人」という状態が保たれます。もし受信側のドメインがクラッシュしても、システムは交換ヒープ上のどのオブジェクトがそのドメインに所有されていたかを追跡できるため（Heap Registry）、メモリリークなしにリソースを回収できます 42。

### **5.4 DMAと安全性**

RustでDMA（Direct Memory Access）を扱う際の課題は、CPUが関与しない間にハードウェアがメモリを書き換えることです。

* **Pinningと所有権:** DMAバッファにはPinトレイトを適用し、メモリ上の移動を禁止します。さらに、DMA転送を開始する際、バッファの所有権を論理的に「ドライバ（ハードウェア）」に移動させます。転送完了割り込みが入るまで、Rustコードからはそのバッファへのアクセス（特に書き込み）を型システムレベルで禁止することで、競合状態を防ぎます 39。

---

## **6\. I/Oサブシステム：ゼロコピーとポーリングの極致**

ExoRustのI/Oサブシステムは、カーネル自体が「カーネルバイパス」アプリケーションのように振る舞うよう設計されます。LinuxのVFS（Virtual File System）やソケットレイヤーのオーバーヘッドを排除します。

### **6.1 ポーリング vs 割り込み：ハイブリッド適応モデル**

高速なネットワーク（10Gbps〜100Gbps）では、パケット到着ごとの割り込み処理がCPUを飽和させる「Receive Livelock」が問題になります。ExoRustはDPDKやLinuxのNAPIと同様のアプローチをカーネルの標準動作とします 44。

* **適応的ポーリング:** トラフィックが少ない時は割り込み駆動（4.2節参照）で動作し、省電力性を確保します。トラフィックが増加し、一定の閾値を超えると、割り込みをマスクし、Executor内の専用タスクがビジーループでNICのリングバッファをポーリングするモードに移行します。これにより、コンテキストスイッチと割り込みオーバーヘッドをゼロにし、キャッシュ効率を最大化します。

### **6.2 ネットワークスタック：真のゼロコピー**

Linuxではsk\_buff構造体が複雑で、プロトコルスタック間でのオーバーヘッドが存在します。ExoRustでは、Rustで記述された軽量なTCP/IPスタック（smoltcpの改良版など）を統合します 46。

* **バッファ管理:** NICのDMAエンジンは、事前に割り当てられた固定サイズのバッファプール（Mempool）に直接パケットを書き込みます。  
* **所有権の連鎖:** パケットが受信されると、そのバッファの所有権は NICドライバ \-\> IP層 \-\> TCP層 \-\> アプリケーション とコピーなしで移動（Move）していきます。アプリケーションがデータを読み終えてバッファを破棄（Drop）すると、バッファは自動的にMempoolに返却され、再利用されます。  
* **ソケットAPIの廃止:** POSIXソケット（socket, bind, listen）は提供しません。代わりに、RustのAsyncRead/AsyncWriteトレイトを実装した非同期ストリームを提供します。

### **6.3 ストレージと非同期ファイルシステム**

NVMe SSDの性能を引き出すため、従来のブロックレイヤーやページキャッシュの概念を刷新します 35。

* **NVMeポーリング:** NVMeドライバは、各CPUコアごとにSubmission/Completion Queueペアを作成し、ロックフリーでコマンドを発行します。  
* **ファイルシステムのバイパス:** データベースなどのアプリケーション向けに、ファイルシステムを通さず、NVMeの名前空間（Namespace）を直接ブロックデバイスとして非同期に操作するAPIを提供します。  
* **ページキャッシュの統合:** ファイルシステムが必要な場合でも、ページキャッシュはカーネルのグローバルヒープ上のArc\<Vec\<u8\>\>などのコレクションとして実装され、VFSのような抽象化層を経由せず、直接メモリオブジェクトとしてアクセスされます。

---

## **7\. デバイスドライバとハードウェア抽象化**

### **7.1 Rustによるドライバ記述**

ExoRustのドライバは、C言語の構造体やマクロに依存せず、Rustのトレイトを活用して記述されます。

* **MMIOの型安全性:** Volatile\<T\>ラッパーやtock-registersクレートのような仕組みを使用し、メモリマップドI/O（MMIO）レジスタへの読み書きを型安全に行います。ビットフィールドの操作ミスなどをコンパイル時に検出します 39。  
* **VirtIOのサポート:** クラウド環境での動作を前提とし、VirtIOドライバ（virtio-net, virtio-blk）を標準サポートします。これらは非同期APIとして実装され、ホスト（ハイパーバイザ）との通信を効率的に行います 50。

### **7.2 ユーザー空間ドライバの統合**

マイクロカーネル的なアプローチとして、PCIデバイスの制御を特定のセル（ドメイン）に委譲することが可能です。IOMMUを活用し、そのデバイスがアクセスできるメモリ範囲を制限することで、ドライバが暴走してもカーネル全体を巻き込まないようにします。ただし、ExoRustではこれもSAS内で行われるため、ドライバとの通信はゼロコピーです 13。

---

## **8\. フォールトアイソレーションと回復メカニズム**

単一アドレス空間であっても、障害分離は必須です。あるアプリケーション（セル）がパニックを起こした場合、システム全体が停止してはなりません。

### **8.1 スタックアンワインドとリソース回収**

Rustのパニック機構（panic\!）は、通常プロセスを終了させますが、ExoRustではこれをドメインの終了処理として実装します 41。

1. **パニック捕捉:** カーネルはカスタムのパニックハンドラを持ちます。  
2. **アンワインディング (Unwinding):** パニック発生地点からスタックを巻き戻します。この過程で、スタック上に存在するローカル変数のデストラクタ（Drop）が実行されます。これにより、ロックの解放、メモリの返却、ソケットのクローズなどが自動的に行われます。  
3. **ドメイン境界:** アンワインドは、そのタスクを生成したドメインの境界（Executorのエントリポイント）で停止します。  
4. **ドメインの破棄:** 障害を起こしたドメインに関連するすべてのタスクとリソース（交換ヒープ上のオブジェクトを含む）を特定し、強制的に解放します。システムは、そのドメインを「停止状態」とし、必要であれば再起動（リロード）を試みます。

### **8.2 RedLeafの知見：交換可能な型とプロキシ**

ドメイン間通信において、パニックが伝播するのを防ぐため、インターフェースには「プロキシ」パターンを使用します。ドメインAがドメインBの関数を呼び出す際、直接呼び出すのではなく、プロキシを経由します。もしドメインB内でパニックが発生した場合、プロキシはそれを捕捉し、ドメインAにはResult::Errとしてエラーを返します。これにより、ドメインAはクラッシュせず、エラー処理（リトライや代替手段の実行）を行うことができます 13。

---

## **9\. セキュリティと攻撃対象領域 (TCB) の最小化**

### **9.1 コンパイラベースのセキュリティ**

ExoRustのセキュリティモデルは、攻撃者が「任意のコード実行」を達成できないことを前提としています。これは、ロードされる全てのコードが検証済みのSafe Rustであること（または署名されたFrameworkコードであること）によって担保されます。

* **バッファオーバーフローの排除:** Rustの境界チェックにより、伝統的なスタック/ヒープオーバーフロー攻撃は原理的に不可能です。  
* **Type Confusionの防止:** 強力な型システムにより、ポインタを整数として扱ったり、異なる型のオブジェクトとして解釈したりする攻撃を防ぎます。

### **9.2 スペクター (Spectre) 等への対策**

SASアーキテクチャの最大の懸念は、サイドチャネル攻撃です。全てが同一アドレス空間にあるため、投機的実行を利用して他のドメインのメモリを読み取る攻撃に対して脆弱になる可能性があります 54。

* **緩和策:**  
  * **Retpoline:** 間接分岐に対する投機的実行の抑制。  
  * **Secretの隔離:** 暗号鍵などの極めて機密性の高いデータは、例外的にハードウェア（CPUのレジスタや専用のセキュアエンクレーブ、あるいはカーネル内の完全に隔離された領域）に保持し、ポインタ経由でのアクセスを制限する設計が必要です。  
  * **スケジューリングのランダム化:** タイミング攻撃を困難にするため、Executorのタスク選択順序にランダム性を導入します。

---

## **10\. 実装ロードマップとフィージビリティ**

この野心的なカーネルを実現するための段階的なロードマップを提示します。

### **フェーズ 1: ブートストラップと基本ランタイム (1-3ヶ月)**

* **目標:** x86\_64ベアメタルでの起動、ロングモード移行、基本アロケータの動作。  
* **技術:** rust-osdev/bootloaderクレートの使用。VGAバッファへの出力。  
* **メモリ:** ビットマップ方式の物理フレームアロケータと、単純なバンプポインタヒープの実装。物理メモリ全体のリニアマッピング確立。

### **フェーズ 2: Async Executorと割り込み基盤 (4-6ヶ月)**

* **目標:** 協調的マルチタスクの実現。  
* **技術:** Futureトレイトの実装、Executorの作成、IDT（割り込み記述子テーブル）のセットアップ。  
* **タスク:** APICタイマーを用いたsleep().awaitの実装。キーボード入力の非同期処理化。

### **フェーズ 3: セルローダーと分離機構 (7-12ヶ月)**

* **目標:** 動的リンクとドメイン分離の実装。  
* **技術:** ELFパーサ（elf\_loader）の組み込み。シンボルテーブルの管理。  
* **安全性:** パニック時のスタックアンワインド機能の実装 (gimliクレート等の活用)。Safe APIの定義と境界の確立。

### **フェーズ 4: 高性能ドライバとネットワーク (2年目)**

* **目標:** 10Gbpsラインレートの達成。  
* **技術:** VirtIOドライバの実装。smoltcpの統合とゼロコピー化。NVMeドライバのポーリング実装。  
* **検証:** QEMU/KVM上でのWebサーバーベンチマーク。Linuxとの比較評価。

---

## **11\. 結論**

本レポートで提案した「ExoRust」アーキテクチャは、Linux/POSIX互換性を捨て去ることで、過去50年間のOSの進化に伴って蓄積された「負債」—コンテキストスイッチ、データコピー、保護リング遷移—を一掃します。

この設計は、汎用的なデスクトップ用途には不向きですが、クラウドマイクロサービス、高頻度トレーディング、エッジコンピューティングといった、特定の単機能アプリケーションがハードウェアの限界性能を要求される領域において、革命的な効率をもたらします。Theseus OSやRedLeafといった先行研究は、このアプローチが理論上だけでなく、工学的にも実現可能であることを示唆しています。Rustという言語が持つ特性をOSの設計レベルで活用することで、安全性とパフォーマンスはもはやトレードオフの関係ではなく、両立可能な属性となるのです。

#### **引用文献**

1. rOOM: A Rust-Based Linux Out of Memory Kernel Component \- J-Stage, 11月 30, 2025にアクセス、 [https://www.jstage.jst.go.jp/article/transinf/E107.D/3/E107.D\_2023MPP0001/\_article/-char/ja](https://www.jstage.jst.go.jp/article/transinf/E107.D/3/E107.D_2023MPP0001/_article/-char/ja)  
2. Principles and Implementation Techniques of Software-Based Fault Isolation \- Now Publishers, 11月 30, 2025にアクセス、 [https://www.nowpublishers.com/article/DownloadSummary/SEC-013](https://www.nowpublishers.com/article/DownloadSummary/SEC-013)  
3. Protection ring \- Wikipedia, 11月 30, 2025にアクセス、 [https://en.wikipedia.org/wiki/Protection\_ring](https://en.wikipedia.org/wiki/Protection_ring)  
4. linux \- What is the overhead of a context-switch? \- Stack Overflow, 11月 30, 2025にアクセス、 [https://stackoverflow.com/questions/21887797/what-is-the-overhead-of-a-context-switch](https://stackoverflow.com/questions/21887797/what-is-the-overhead-of-a-context-switch)  
5. Context switches on Linux are a pretty heavy affair, this is the result of some ... \- Hacker News, 11月 30, 2025にアクセス、 [https://news.ycombinator.com/item?id=28537436](https://news.ycombinator.com/item?id=28537436)  
6. What is the point of single address space? \- OSDev.org, 11月 30, 2025にアクセス、 [https://f.osdev.org/viewtopic.php?t=26098](https://f.osdev.org/viewtopic.php?t=26098)  
7. System calls overhead \- Stack Overflow, 11月 30, 2025にアクセス、 [https://stackoverflow.com/questions/23599074/system-calls-overhead](https://stackoverflow.com/questions/23599074/system-calls-overhead)  
8. Rewrite the Linux kernel in Rust?, 11月 30, 2025にアクセス、 [https://dominuscarnufex.github.io/cours/rs-kernel/en.html](https://dominuscarnufex.github.io/cours/rs-kernel/en.html)  
9. MSG\_ZEROCOPY \- The Linux Kernel documentation, 11月 30, 2025にアクセス、 [https://docs.kernel.org/networking/msg\_zerocopy.html](https://docs.kernel.org/networking/msg_zerocopy.html)  
10. Zero-copy: Principle and Implementation | by Zhenyuan (Zane) Zhang | Medium, 11月 30, 2025にアクセス、 [https://medium.com/@kaixin667689/zero-copy-principle-and-implementation-9a5220a62ffd](https://medium.com/@kaixin667689/zero-copy-principle-and-implementation-9a5220a62ffd)  
11. Ultimate Rust Performance Optimization Guide 2024: Basics to Advanced, 11月 30, 2025にアクセス、 [https://www.rapidinnovation.io/post/performance-optimization-techniques-in-rust](https://www.rapidinnovation.io/post/performance-optimization-techniques-in-rust)  
12. A Low-Latency Optimization of a Rust-Based Secure Operating System for Embedded Devices \- PMC \- PubMed Central, 11月 30, 2025にアクセス、 [https://pmc.ncbi.nlm.nih.gov/articles/PMC9692816/](https://pmc.ncbi.nlm.nih.gov/articles/PMC9692816/)  
13. RedLeaf: Isolation and Communication in a Safe Operating System | USENIX, 11月 30, 2025にアクセス、 [https://www.usenix.org/system/files/osdi20-narayanan\_vikram.pdf](https://www.usenix.org/system/files/osdi20-narayanan_vikram.pdf)  
14. Theseus: an Experiment in Operating System Structure and State Management \- USENIX, 11月 30, 2025にアクセス、 [https://www.usenix.org/conference/osdi20/presentation/boos](https://www.usenix.org/conference/osdi20/presentation/boos)  
15. Design and Structure of Theseus \- The Theseus OS Book, 11月 30, 2025にアクセス、 [https://www.theseus-os.com/Theseus/book/design/design.html](https://www.theseus-os.com/Theseus/book/design/design.html)  
16. (PDF) Single Address Space Operating Systems \- ResearchGate, 11月 30, 2025にアクセス、 [https://www.researchgate.net/publication/2570875\_Single\_Address\_Space\_Operating\_Systems](https://www.researchgate.net/publication/2570875_Single_Address_Space_Operating_Systems)  
17. Theseus: an Experiment in Operating System Structure and State Management \- USENIX, 11月 30, 2025にアクセス、 [https://www.usenix.org/system/files/osdi20-boos.pdf](https://www.usenix.org/system/files/osdi20-boos.pdf)  
18. Asterinas: A Linux ABI-Compatible, Rust-Based Framekernel OS with a Small and Sound TCB \- arXiv, 11月 30, 2025にアクセス、 [https://arxiv.org/html/2506.03876v1](https://arxiv.org/html/2506.03876v1)  
19. Async/Await | Writing an OS in Rust, 11月 30, 2025にアクセス、 [https://os.phil-opp.com/async-await/](https://os.phil-opp.com/async-await/)  
20. The Framekernel Architecture \- The Asterinas Book, 11月 30, 2025にアクセス、 [https://asterinas.github.io/book/kernel/the-framekernel-architecture.html](https://asterinas.github.io/book/kernel/the-framekernel-architecture.html)  
21. Single address space operating system \- Wikipedia, 11月 30, 2025にアクセス、 [https://en.wikipedia.org/wiki/Single\_address\_space\_operating\_system](https://en.wikipedia.org/wiki/Single_address_space_operating_system)  
22. Sharing and protection in a single-address-space operating system \- University of Washington, 11月 30, 2025にアクセス、 [https://homes.cs.washington.edu/\~levy/opal.pdf](https://homes.cs.washington.edu/~levy/opal.pdf)  
23. single common address space for all tasks \- Stack Overflow, 11月 30, 2025にアクセス、 [https://stackoverflow.com/questions/2798645/single-common-address-space-for-all-tasks](https://stackoverflow.com/questions/2798645/single-common-address-space-for-all-tasks)  
24. Exploring Rust for Unikernel Development, 11月 30, 2025にアクセス、 [https://plos-workshop.org/2019/preprint/plos19-lankes.pdf](https://plos-workshop.org/2019/preprint/plos19-lankes.pdf)  
25. Another Rust-y OS: Theseus joins Redox in pursuit of safer, more resilient systems, 11月 30, 2025にアクセス、 [https://www.theregister.com/2021/01/14/rust\_os\_theseus/](https://www.theregister.com/2021/01/14/rust_os_theseus/)  
26. Theseus: an Experiment in Operating System Structure and State Management, 11月 30, 2025にアクセス、 [https://systems-rg.github.io/slides/2022-05-06-theseus.pdf](https://systems-rg.github.io/slides/2022-05-06-theseus.pdf)  
27. Asterinas: A Linux ABI-Compatible, Rust-Based Framekernel OS with a Small and Sound TCB \- USENIX, 11月 30, 2025にアクセス、 [https://www.usenix.org/system/files/atc25-peng-yuke.pdf](https://www.usenix.org/system/files/atc25-peng-yuke.pdf)  
28. Kernel Memory Safety: Mission Accomplished \- Asterinas, 11月 30, 2025にアクセス、 [https://asterinas.github.io/2025/06/04/kernel-memory-safety-mission-accomplished.html](https://asterinas.github.io/2025/06/04/kernel-memory-safety-mission-accomplished.html)  
29. Combining Type Checking and Formal Verification for Lightweight OS Correctness \- arXiv, 11月 30, 2025にアクセス、 [https://arxiv.org/abs/2501.00248](https://arxiv.org/abs/2501.00248)  
30. Writing an OS in Rust: Async/Await \- Hacker News, 11月 30, 2025にアクセス、 [https://news.ycombinator.com/item?id=22727985](https://news.ycombinator.com/item?id=22727985)  
31. Async/Await Is Real And Can Hurt You : r/rust \- Reddit, 11月 30, 2025にアクセス、 [https://www.reddit.com/r/rust/comments/1gvmtok/asyncawait\_is\_real\_and\_can\_hurt\_you/](https://www.reddit.com/r/rust/comments/1gvmtok/asyncawait_is_real_and_can_hurt_you/)  
32. Task Wakeups with Waker \- Asynchronous Programming in Rust, 11月 30, 2025にアクセス、 [https://rust-lang.github.io/async-book/02\_execution/03\_wakeups.html](https://rust-lang.github.io/async-book/02_execution/03_wakeups.html)  
33. How to drive/wake up a Future with an hardware interrupt \- Rust Users Forum, 11月 30, 2025にアクセス、 [https://users.rust-lang.org/t/how-to-drive-wake-up-a-future-with-an-hardware-interrupt/31622](https://users.rust-lang.org/t/how-to-drive-wake-up-a-future-with-an-hardware-interrupt/31622)  
34. Implementing async/await in my rust kernel \- YouTube, 11月 30, 2025にアクセス、 [https://www.youtube.com/watch?v=SN2U4XkbHTA](https://www.youtube.com/watch?v=SN2U4XkbHTA)  
35. Introducing Glommio, a thread-per-core crate for Rust and Linux | Datadog, 11月 30, 2025にアクセス、 [https://www.datadoghq.com/blog/engineering/introducing-glommio/](https://www.datadoghq.com/blog/engineering/introducing-glommio/)  
36. An Embedded Rust Operating System for Networked Sensors & Multi-Core Microcontrollers. In Proc. of the 21st IEEE International Conference on Distributed Computing in Smart Systems and the Internet of Things (DCOSS-IoT), June 2025\. Ariel OS \- arXiv, 11月 30, 2025にアクセス、 [https://arxiv.org/html/2504.19662](https://arxiv.org/html/2504.19662)  
37. Case against “maybe \`async\`” \- language design \- Rust Internals, 11月 30, 2025にアクセス、 [https://internals.rust-lang.org/t/case-against-maybe-async/20144](https://internals.rust-lang.org/t/case-against-maybe-async/20144)  
38. Is async/await a good idea for an OS kernel, even a toy one? Cooperative multita... | Hacker News, 11月 30, 2025にアクセス、 [https://news.ycombinator.com/item?id=22729461](https://news.ycombinator.com/item?id=22729461)  
39. virtio\_drivers \- Rust \- Docs.rs, 11月 30, 2025にアクセス、 [https://docs.rs/virtio-drivers](https://docs.rs/virtio-drivers)  
40. Extending Rust with Support for Zero Copy Communication \- Vikram, 11月 30, 2025にアクセス、 [https://arkivm.github.io/publications/2023-plos-rust-zerocopy.pdf](https://arkivm.github.io/publications/2023-plos-rust-zerocopy.pdf)  
41. Isolation in Rust: What is Missing?, 11月 30, 2025にアクセス、 [https://par.nsf.gov/servlets/purl/10386701](https://par.nsf.gov/servlets/purl/10386701)  
42. RedLeaf: Isolation and Communication in a Safe Operating System, 11月 30, 2025にアクセス、 [https://www.cse.wustl.edu/\~roger/566S.s21/RedLeaf\_%20Isolation%20and%20Communication%20in%20a%20Safe%20Operating%20System.pdf](https://www.cse.wustl.edu/~roger/566S.s21/RedLeaf_%20Isolation%20and%20Communication%20in%20a%20Safe%20Operating%20System.pdf)  
43. Resistance to Rust abstractions for DMA mapping \- LWN.net, 11月 30, 2025にアクセス、 [https://lwn.net/Articles/1006805/](https://lwn.net/Articles/1006805/)  
44. High performance networking applications in rust? \- Reddit, 11月 30, 2025にアクセス、 [https://www.reddit.com/r/rust/comments/11d6jei/high\_performance\_networking\_applications\_in\_rust/](https://www.reddit.com/r/rust/comments/11d6jei/high_performance_networking_applications_in_rust/)  
45. Zero-copy network transmission with io\_uring \- LWN.net, 11月 30, 2025にアクセス、 [https://lwn.net/Articles/879724/](https://lwn.net/Articles/879724/)  
46. The Design and Implementation of a New User-level DPDK TCP Stack in Rust \- YouTube, 11月 30, 2025にアクセス、 [https://www.youtube.com/watch?v=KtWjRevZcio](https://www.youtube.com/watch?v=KtWjRevZcio)  
47. netmap-rs \- crates.io: Rust Package Registry, 11月 30, 2025にアクセス、 [https://crates.io/crates/netmap-rs](https://crates.io/crates/netmap-rs)  
48. Understanding Modern Storage APIs: A systematic study of libaio, SPDK, and io\_uring \- Large Research, 11月 30, 2025にアクセス、 [https://atlarge-research.com/pdfs/2022-systor-apis.pdf](https://atlarge-research.com/pdfs/2022-systor-apis.pdf)  
49. An Empirical Study of Rust-for-Linux: The Success, Dissatisfaction, and Compromise \- Mengwei Xu, 11月 30, 2025にアクセス、 [https://xumengwei.github.io/files/ATC24-RFL.pdf](https://xumengwei.github.io/files/ATC24-RFL.pdf)  
50. Stardust Oxide: I wrote a unikernel in Rust for my bachelors dissertation \- Reddit, 11月 30, 2025にアクセス、 [https://www.reddit.com/r/rust/comments/ta85iy/stardust\_oxide\_i\_wrote\_a\_unikernel\_in\_rust\_for\_my/](https://www.reddit.com/r/rust/comments/ta85iy/stardust_oxide_i_wrote_a_unikernel_in_rust_for_my/)  
51. rcore-os/virtio-drivers: VirtIO guest drivers in Rust. \- GitHub, 11月 30, 2025にアクセス、 [https://github.com/rcore-os/virtio-drivers](https://github.com/rcore-os/virtio-drivers)  
52. tokio-vsock — async Rust library // Lib.rs, 11月 30, 2025にアクセス、 [https://lib.rs/crates/tokio-vsock](https://lib.rs/crates/tokio-vsock)  
53. RedLeaf: Isolation and Communication in a Safe Operating System \- USENIX, 11月 30, 2025にアクセス、 [https://www.usenix.org/conference/osdi20/presentation/narayanan-vikram](https://www.usenix.org/conference/osdi20/presentation/narayanan-vikram)  
54. Anyone using io\_uring? : r/rust \- Reddit, 11月 30, 2025にアクセス、 [https://www.reddit.com/r/rust/comments/wrecb9/anyone\_using\_io\_uring/](https://www.reddit.com/r/rust/comments/wrecb9/anyone_using_io_uring/)  
55. Memory Safety is Merely Table Stakes | USENIX, 11月 30, 2025にアクセス、 [https://www.usenix.org/publications/loginonline/memory-safety-merely-table-stakes](https://www.usenix.org/publications/loginonline/memory-safety-merely-table-stakes)
