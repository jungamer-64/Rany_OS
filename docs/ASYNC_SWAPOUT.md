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

次のアクション: `kernel/src/mm/async_swapout.rs` のスケルトン実装と `mm/mod.rs` への登録、
`page_reclaim.rs` のキュー呼び出し埋め込みを行います（まずはテスト用実装）。