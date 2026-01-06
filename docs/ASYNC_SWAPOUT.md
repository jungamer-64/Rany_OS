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

