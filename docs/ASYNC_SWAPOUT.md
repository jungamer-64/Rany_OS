# 非同期スワップアウト & 書き戻し合流 (Async Swapout / Writeback Merge)

目的

- ページ回収（reclaim）時にダーティなページを効率的に書き戻し（ファイル書き込み / スワップアウト）、
  書き戻し完了時にフレームを非同期的に解放してメモリ圧力を低減する。
- ファイルバックページについては精密なページ単位の書き戻しを優先し、
  既存の全体同期 (`page_cache().sync_all`) をフォールバックとする。
- 匿名ページについては `zswap`（圧縮メモリキャッシュ）へまず格納を試み、失敗時は通常スワップへフォールバック（未実装なら一時的に破棄/保留）。

主要コンポーネント

- AsyncSwapoutManager (kernel/src/mm/async_swapout.rs)
  - エントリキュー（bounded） + ワーカスレッド
  - `try_enqueue_swapout(frame: FrameIndex, kind: SwapKind) -> Result<SwapHandle, SwapError>`
  - `SwapKind::File { ino: InodeNum, page_num: u64 }` / `SwapKind::Anon`
  - 完了通知用の `SwapHandle::wait()` / `is_done()`
  - 内部で "pending" セットを保持して二重キュー化を防止

- PageCache の書き戻し呼び出し
  - 既存の `PageCache::sync_page(ino, page_num, writer)` をワーカ内で呼ぶ
  - `writer` は `write_inode_by_number(ino, offset, data)` を呼ぶ

- 統合（page_reclaim側）
  - ダーティページ発見時に `try_enqueue_swapout` を試みる
  - キューイング成功時はそのフレームの解放をワーカに委譲（reclaim スレッドは解放せず次へ）
  - キューイング失敗時は従来の同期的書き戻しにフォールバック

- memcg の不変量
  - フレームの最終解放は buddy_dealloc_frame 経路により行い，その中で `memcg_untrack_page` / `memcg_uncharge` を実行する（既存挙動を利用）
  - したがって、ワーカは書き戻し完了後に `frame_backing::untrack_frame_backing(frame)` → `buddy_dealloc_frame(phys_frame)` を呼べばよい

実装方針（段階的）

1. テスト限定のワーカ実装（`cfg(test)`）を用意し、ユニットテストで機能を検証する
2. API を安定化させ、将来的なカーネル環境（executor/ワーカー）へ移行可能にする
3. 匿名ページのZSWAP統合、スワップ領域実装との連携
4. バックプレッシャ、バッチ書き戻し、QoS（優先度）を追加

テスト

- ファイルバックページの非同期書き戻しテスト
  - page cache にページを挿入/dirty にし、対応するフレームをトラックして`try_enqueue_swapout` を呼ぶ
  - ワーカが書き戻し→`frame_backing`が解除→フレームが解放されることを確認
- 匿名ページの zswap 書き込み成功/失敗シナリオ
- 複数エントリの同時キューイングと同一フレーム二重キュー化回避

安全性/注意点

- ワーカは `buddy_dealloc_frame` を用いてフレーム解放を行う（これにより memcg 側の untrack/uncharge が行われる）
- データ競合（同じフレームの重複処理）を防ぐため pending セットを導入する
- カーネル実装時には IRQ/割り込みコンテキストやロック順序に配慮する（テスト実装では std::thread を使用）

---

## プロダクションワーカ設計（Kernel-safe Persistent Worker）

### 目的

- カーネル実行環境（no_std）で安全に動作する永続バックグラウンドワーカを実装し、
  ダーティページの非同期書き戻し・スワップアウトを効率的に処理する。
- 書き戻し/スワップ完了時にフレームを確実に解放してメモリ圧力を緩和し、
  MemCG の不変量（トラック / アンチャージ）を保持する。

### 要求仕様（高レベル）

- `try_enqueue_swapout(frame: FrameIndex, kind: SwapKind) -> Result<SwapHandle, SwapError>` は非ブロッキングで高速に失敗を返せること（呼び出し元はフォールバック可能）。
- キューはバウンド容量を持ち、バックプレッシャを提供する（QueueFull を返す）。
- 二重キュー化防止のため `pending` セットを保持する。
- ワーカは Executor の Task として永続的に実行され、バッチ処理と遅延ポーリングで IO のスループットとレイテンシを両立する。
- 優先度（ファイル書き戻しを優先）や QoS を将来導入できる設計にする。

### API と失敗モード

- 成功: `Ok(SwapHandle)`（非同期完了を待てるハンドル、もしくは空ハンドル）
- 失敗: `SwapError::AlreadyPending`（同じフレームが既に処理待ち）、`SwapError::QueueFull`（容量不足）、`SwapError::NotSupported`（環境上未サポート）

呼び出し側（page_reclaim）は `AlreadyPending` / `QueueFull` を受け取った場合に同期フォールバック（該当ページの即時 writeback または global sync）を行う。

### キュー実装方針

- 最終設計は lock-free のリングバッファを目指すが、まずは `spin::Mutex` + `VecDeque` ベースで `try_lock()` を利用した非ブロッキング合成を実装する（テストしやすさと安全性優先）。
- `try_enqueue_swapout` は `try_lock()` に失敗した場合に即座に `QueueFull` を返す（ISRでの呼出を想定しないが、呼び出しが短時間で済むことを保証する）。
- `pending` セットで二重登録を防ぎ、書き戻し完了で `pending` を解除する。

### ワーカ実行モデル

- Executor 上の永続 Task として実装し、ループ内で `WaitForWork` を await → バッチを取り出して処理。
- 1ループあたりの最大処理数は `BATCH_SIZE` で制限し、各バッチ後に `yield`（await の形で）して長時間のブロッキングを避ける。
- ファイルページは `PageCache::sync_page(ino,page,writer)` を用いて精密書き戻しを試みる。書き戻し成功時に `frame_backing::untrack_frame_backing()` → `buddy_dealloc_frame()` を行う（これにより memcg のアンチャージが行われる既存経路を利用）。
- 匿名ページはまず `zswap` に格納を試み、成功／失敗に関わらずフレームは `buddy_dealloc_frame()` で返却（zswap miss 時は後続で swap-on-disk 実装を試みる）。

### バックプレッシャ & 優先度

- キューの閾値（high_water, reserve_for_file 等）を設け、ファイル書き戻し用の予約容量を検討する。
- 動的バックプレッシャ（トークンバケット）を導入: 匿名ページのエントリはトークン消費によりレート制御され、ワーカのバッチ処理完了時にトークンがリフィルされる。これにより突発的な anon エントリの急増を抑えつつ、進行性を維持できる。

### パラメータとチューニング

- TOKEN_BUCKET_CAPACITY（バースト容量）: 推奨値は `CHANNEL_SIZE / 4`（実装上の初期値）。大きめに設定すると突発負荷を吸収しやすくなるが、anon エントリがファイル書き戻しを阻害するリスクがある。
- TOKEN_REFILL_PER_BATCH（リフィル量）: 推奨値は `BATCH_SIZE / 2`。バッチ処理のたびに一定量を回復する設計で、I/O のスループットと公平性のバランスを取る。
- RESERVED_FILE_SLOTS（ファイル予約）: キュー容量の約 12.5% を予約してファイル書き戻しを優先する実装にしています。システムの I/O 特性により調整してください。

調整の指針:

- レイテンシ重視（短時間で anon を積極的に解放したい）: `TOKEN_BUCKET_CAPACITY` を増やし、`TOKEN_REFILL_PER_BATCH` を小さめにする。
- スループット重視（ファイル書き戻し優先）: `RESERVED_FILE_SLOTS` を増やし、`TOKEN_BUCKET_CAPACITY` を控えめにする。

### 調整チェックリスト（実践） ✅

1. ベースラインを取得する（5–10分）
   - 概要: 現行パラメータの下で軽負荷→中負荷テストを実行し、メトリクスを収集します。
   - 実行例: `cargo test -p rany_kernel --lib -- --ignored --nocapture`（`test_async_swapout_heavy_stress` / `bench_enqueue_throughput` を含む）
   - 収集対象: `queued_counts()`（総キュー長, fileキュー長）, `token_count()`（トークン残量）, `writeback_skipped`, `enqueue_failures`（QueueFull 発生回数）, ワーカの処理遅延

2. 問題の初期判別と目安
   - QueueFull が頻発（enqueue 失敗率が高い）: CHANNEL_SIZE を増やす、あるいは anon の `TOKEN_BUCKET_CAPACITY` を減らしてファイルスロットを優先する。BATCH_SIZE やワーカ処理能力の引き上げも検討。
   - file_queue が予約枠に張り付く: `RESERVED_FILE_SLOTS` を増やす。
   - token_count が常に 0 に張り付く: `TOKEN_REFILL_PER_BATCH` または `TOKEN_BUCKET_CAPACITY` を増やす。
   - writeback_skipped / writeback_failures が発生: ストレージ IO エラーログを確認し、必要なら一時的に同期書き戻し（`sync_all`）の頻度を上げる。

3. 変更は一度に一つ、短時間で観測する
   - 1つのパラメータ変更 → 5–10 分運用 → 収集結果の比較
   - 複数のパラメータを同時に変えると原因切り分けが難しくなります。

### メトリクスの解釈 (具体例) 📊

- 平均 `queued_count` が `CHANNEL_SIZE * 0.75` を超えて常時推移 → キューが逼迫している。CHANNEL_SIZE 増加 or worker throughput の改善が必要。
- `file_queue` が `RESERVED_FILE_SLOTS` を常に占有 → ファイル書き戻しが滞っている。`RESERVED_FILE_SLOTS` を増やすか I/O レイテンシを下げる。
- `token_count` が 0 に固定 → 匿名ページがレート制御されすぎであり、スループットの低下を招く。リフィル量か容量の増加を検討。
- `QueueFull` の短期的スパイク → 一時的には許容可能。頻発するならパラメータ調整またはワーカ増強を検討。
- `writeback_skipped > 0` → 根本はストレージエラーまたは書き込み競合。ログを精査し、必要なら穏やかな fallback を増やす。

### 実践コマンド例（Windows / PowerShell） 🔧

- 全ての重いテストを手動で実行してログを取得:
  - powershell -Command "cargo test -p rany_kernel --lib -- --ignored --nocapture" | tee async_swapout_stress.log
- 1分毎に簡易モニタを回してメトリクスをログに落とす（テスト中別セッションで実行する想定）:
  - powershell -Command "while ($true) { python - <<'PY'
import time,subprocess,sys
p=subprocess.run(['cargo','test','-p','rany_kernel','--lib','--','--nocapture','--test-threads=1','-q'],capture_output=True,text=True)
print(p.stdout)
time.sleep(60)
PY
}"

注: 実環境では `queued_counts()`/`token_count()` を露出する調査用フック（または trace/log 出力）を使って長時間監視する方が安定した傾向把握に有効です。

---

### テストとベンチの実行方法

- 単体テスト（軽量、CI向け）: `cargo test -p rany_kernel --lib`（デフォルトで無視される重いテストは実行されません）
- 重いストレステストとベンチ（手動実行）: `cargo test -p rany_kernel --lib -- --ignored --nocapture`（`test_async_swapout_heavy_stress` と `bench_enqueue_throughput` は `#[ignore]` です）
- モニタリング: `queued_counts()` と `token_count()` を使ってキュー長と anon トークン残量を監視できます（テスト/カーネル両方で対応しています）。

---

- キュー満杯時は `QueueFull` を返し、page_reclaim 側で同期書き戻しへフォールバックすることで進行性を担保する。

### エラーと代替経路

- 書き込み失敗時は global `page_cache().sync_all()` にフォールバックして再試行・進行性を確保する。
- それでも進展しない場合は `writeback_skipped` カウントをインクリメントして回収をスキップする（再試行は将来の reclaim パスに委ねる）。

### セーフティ / MemCG 不変量

- フレームの最終解放は `buddy_dealloc_frame()` 経路で行い、各 4KiB 単位で `memcg_untrack_page()` / `memcg_uncharge()` が行われることを前提とする。
- ワーカは書き戻し成功を確認してからフレームを解放する。書き戻し失敗時はフォールバック経路で解放・アンチャージを行うか、スキップカウントを増やして明示する。

### テスト計画

- 単体: ファイル書き戻しの非同期完了、二重キュー化の回避（AlreadyPending）、QueueFull の返却
- 統合: 高並列の enqueue と reclaim をシミュレートして memcg 不変量（アンチャージの二重実行やリーク）が発生しないことを確認
- ストレス: キューが満杯になった際のフォールバック動作・遅延特性を検証

### ワーカのインスペクションと停止（カーネル用 API）

- `queued_counts() -> (usize, usize)`: 現在の総キュー長とファイル書き戻しエントリ数を返す（監視 / メトリクス向け）
- `is_worker_running() -> bool`: ワーカが稼働中かどうかを返す
- `start_worker()`: ワーカを明示的に起動・再開する（`stop_worker()` による停止後に再開可能）
- `stop_worker()`: ワーカに対してグレースフルシャットダウンをリクエストする（キューが空くまで現在の処理を継続し、その後停止することを試みる）。

---

次のアクション:

1) この設計をもとに `kernel/src/mm/async_swapout.rs` のプロダクション実装を進める（まずは `try_lock()` ベースのバウンドキュー）
2) カーネル向けバウンドキュープリミティブを実装しユニットテストを追加
3) ワーカを `Executor` に統合し、優先度・バッチング・バックプレッシャを実装して統合テストを追加
4) パフォーマンスと memcg 保証のためのストレステストを実行し設計を調整する
