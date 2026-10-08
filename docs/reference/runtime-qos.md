# Runtime QoS / Resource Accounting Reference

- Status: Reference
- Audience: scheduler、公平性、OOM、帯域制御の現行方針を確認したい contributor
- Related: [../architecture.md](../architecture.md), [resilience-recovery.md](resilience-recovery.md), [api-reference.md](api-reference.md), [deprecations.md](deprecations.md)

この文書は ExoRust の runtime QoS / resource accounting の reference です。競合時は
[../architecture.md](../architecture.md) と
[../kernel-development-guidelines.md](../kernel-development-guidelines.md)
を優先してください。

## 位置付け

- runtime QoS は authority とは別の policy である。
- Capability や署名検証は「何が許されるか」を決め、quota / OOM / bandwidth shaping は「どの程度まで資源を使えるか」を決める。
- canonical baseline では、resource accounting は domain 単位で行う。
- replication / checkpoint / restart policy などの resilience は
  [resilience-recovery.md](resilience-recovery.md)
  に分離して扱う。

## 現行実装

### 1. QuotaManager

- 実装:
  [../../kernel/src/domain/quota.rs](../../kernel/src/domain/quota.rs)
- グローバル入口:
  - `quota_manager()`
  - `init()`
- 現行の主要 API:
  - `consume_cpu_time()`
  - `try_network_io()`
  - `try_storage_io()`
  - `select_oom_victim()`
  - `get_stats()`

### 2. 資源モデル

- CPU quota:
  実行した断片ごとの CPU 時間を period 単位で課金する。待機時間と他タスクの実行時間を含めず、SMP の期間更新・集計は直列化する。超過したタスクは quota 待ちへ移し、後続タスクの選択を妨げない。
- memory quota:
  実行コンテキストを入れる時に安定した課金先へ binding を取得する。通常の heap 割り当ては binding を直接使い、共有レジストリのロックや `Arc` 複製を行わない。課金済みの非 `Copy` 所有値を allocation header が保持し、別 CPU の解放でも元の課金先へ一度だけ返す。raw allocation が失敗した時も、この所有値の返却で課金を巻き戻す。
- quota の再登録は policy 更新として扱い、既存の使用量をリセットしない。byte 上限は MiB へ丸めず、指定値をそのまま使う。上限を使用量未満へ下げた場合は既存 allocation を保持し、返却が進むまで新規 admission を拒否する。
- ドメインの quota を削除すると新規 binding / charge を停止する。実行 binding と未返却 charge がなくなるまで account backing を保持し、cold な登録・観測・OOM 操作で回収する。同じ domain ID でも未返却の account がある間は再登録を拒否する。未登録、終了済み、上限超過、競合、集計 overflow、metadata 確保失敗を区別する。
- execution admission は live domain の security snapshot と quota binding を別々に取得する。対象不在・終了済み・registry 不可用では security を構築せず、quota の拒否とも区別する。失敗時は CPU に既存の実行 context を保持し、kernel の credentials / Capability へ置き換えない。
- network / storage I/O:
  token bucket 型の帯域制御を使う。
- priority:
  タスクとドメインの `Low / Normal / High / Critical` の正の重みを乗算し、仮想実行時間で公平な進行を与える。ドメイン優先度は OOM victim selection にも影響する。

### 3. OOM 経路

- OOM victim selection は quota 側の priority と使用量に基づく。
- heap 側の OOM 実装は quota manager を authoritative source として使う。
- OOM の選択・終了処理は kernel の課金先で実行し、起点 domain の quota が枯渇・終了しても bookkeeping を続けられるようにする。課金先の切替は registry lock や metadata 確保を伴わず、destructor が動く場合も起点の domain・credentials・Capability を保持する。終了開始時に新規 admission を止め、起点の実行 binding は処理が戻るまで保持する。
- ドメイン終了は停止要求と回収完了を分ける。実行中・中断中の poll、コード lease、未完了の finalizer がある間は型付きの未完了を返して資源を保持する。回収完了と依存先通知を一度の registry publication で確定する。回収中の通知は依存先 ID を保持し、表示時に文字列化する。registry 内では quota の admission を停止するだけで metadata を破棄せず、回収処理はロックの外で行う。回収処理が戻るまで account binding を保持し、同じ domain の再 admission を拒否する。停止要求前の拒否は未進行であり、kernel 保護・対象不在・registry 不可用・quota 拒否を区別する。終了成功は、保持中の RAM や DMA quarantine の返却完了を意味しない。
- ドメイン終了後に未返却の課金が残っていても、解放量として計上しない。終了前後の課金差分は返却済み payload byte 数を表し、物理 RAM の返却量とは区別する。cache / pool が返した物理領域は別の回収量として扱う。
- CPU cache の drain は、ヒープへ返した予約ブロック量と PMM へ実際に返した物理量を別々に保持する。Exchange Heap の返却は前者であり、boot 所有領域を PMM へ返した証拠ではない。slab の最後の予約が返りページを退役した場合は、予約ブロック量とページ全体の物理量の両方を記録する。途中失敗でも完了済みの返却量を保持し、quota 返却量とは合算しない。
- Buddy の未公開貸与領域は、最初の割り当てと pool link の公開が一度に成立するまで準備所有値が保持する。競合・poison・サイズ不一致では同じ未公開所有値を返す。破棄時は共有 pool guard の外で metadata と payload の両方を PMM へ返し、公開済み領域は最後の live block が返るまで保持する。
- Buddy の返却は予約の所有権を消費し、返却済みブロック内の記録へ移す。記録の公開はブロックと領域への最後のアクセスであり、新規 metadata 確保や pool lock の待機を必要としない。記録は領域の live 数に含まれ、node の guard が取り込んで free list へ返すまで backing を保持する。圧迫回収は記録の有限な snapshot を処理し、回復したヒープ容量と PMM へ返した物理量を区別する。領域内に live block が残っていても、利用可能な容量の回復は OOM の進捗となる。
- slab の補充と最後の予約の返却は共有 lock の取得を一度だけ試す。占有情報の返却後に lock を取得できなくても、そのページの所有値は node pool に残る。既存の OOM 経路は未処理の空ページも回収し、live な予約を持つページは退役しない。poison の自動解除や、延期した返却を完了済みの物理量として計上することはしない。
- 4KiB / zeroed 補充は要求へ返すフレームを先に確保し、残りだけを元の CPU の短い借用で公開する。CPU 移動・再入借用・満杯で公開できない所有値は PMM へ返す。zeroed 補充の途中で RAM が枯渇しても確保済みの要求フレームを返し、追加確保を要求しない。公開していない zeroed batch の破棄は所有値を同期返却する。
- 2MiB cache は完全な 2MiB サイズ・実アドレス alignment・返却先 node を受け入れ時に検証し、各 node の保持は最大 4 枚とする。割り当て・返却は一度の lock 試行だけを行い、競合・poison では保持済み所有値を変更しない。割り当ては同じ node の PMM occupancy へ進み、返却の未受理所有値は lock guard の外で同期返却する。キャッシュは RAM の返却権限を新たに生成しない。
- 共有 slab / Buddy / Huge Page pool の圧迫回収は各 pool のロックを一度だけ試行する。競合時は所有値を保持して次の回収 pass に委ね、poison 時は通常の mutation authority を与えない。結果は返却済み物理 byte 数、回復したヒープ容量、競合・poison による延期数を分けて保持する。pool を外してから PMM へ返し、GlobalAlloc の回収処理で他 CPU のロック取得を待ち続けない。
- 再起動は停止完了したドメインの実行を再開し、既存の Future と課金先を保持する。終了済みのドメインは再開しない。policy / 状態変更に失敗した時は理由を保持して caller へ返し、成功扱いで状態を進めない。driver load の policy 失敗には、既に作成した cell / domain の識別子も含め、cleanup の責任を失わない。

### 4. 観測面

- ExoShell / KAPI の公開観測面は意図的に絞られている。
- `task.stats()` / `task.fuel()` / `task.preemption()` は scheduler / fairness 診断の入口である。
- `sys.monitor()` は heap / task / domain / network などの集約 snapshot を返す。
- quota の内部 API そのものを一般公開 API に昇格させることは、この文書の目的ではない。

## 非目標

- Capability と priority を結び付けて権限昇格を決めること
- multi-tenant SLA scheduler を現行 canonical として固定すること
- ad hoc な subsystem ごとの独自 OOM killer を増やすこと

## 関連文書

- [../architecture.md](../architecture.md)
- [../kernel-development-guidelines.md](../kernel-development-guidelines.md)
- [resilience-recovery.md](resilience-recovery.md)
- [api-reference.md](api-reference.md)
- [deprecations.md](deprecations.md)
