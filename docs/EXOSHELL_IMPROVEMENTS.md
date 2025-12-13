ExoShell 改善設計案
=====================

概要
----

このドキュメントは `ExoShell` の設計改善案（ゼロコピー、Capability セキュリティ、Async-First, GUI 最適化）をまとめたものです。既にコードベースに対していくつかの安全性・非同期化・拡張性の改善パッチを適用しました（`cap.grant` の権限強化、名前空間の動的登録、Graphical shell のキーボード IRQ/Waker 利用、式評価の再帰深度制限）。

優先対応提案（実装手順）
----------------------

1) ExoValue のゼロコピー化（RRef/Cow 導入）
   - 背景: 現状 `ExoValue::Bytes(Cow<'a, [u8]>)` を使っているが、カーネルのページキャッシュ / DMA バッファを直接参照するために `RRef`（設計案にあるやり方）や `Arc<[u8]>` を使った "shared buffer" 型が望ましい。
   - 方針:
     1. 新たに `pub enum ExoBuffer { Owned(Vec<u8>), Shared(Arc<[u8]>), Borrowed(&'a [u8]) /* 将来的に: RRef */ }` を導入
     2. `ExoValue::Bytes` を `ExoValue::Buffer(ExoBuffer)` に置換（段階的に置く）。既存 API の互換を保つために `From<Vec<u8>>` / `From<Arc<[u8]>>` を実装。
     3. `fs::read()` を変更して、もし VFS が zero-copy をサポートする場合は `Shared`/`Borrowed` を返す。未サポート時は `Owned` を返す。
   - 注意点:
     - Lifetime 管理と所有権（RRef の場合は交換ヒープの所有と回収）
     - ユーザーランド（shell）側の API は変更を最小限に留め、`to_owned_bytes()` のような互換メソッドを提供

2) Capability の堅牢化
   - 既に行った改善:
     - `cap.grant` において、呼び出しドメインが `CAP_SYS_ADMIN` を持つか、付与対象 capability を `permitted` に持っている場合のみ許可するように変更
     - `cap.grant` の dynamic dispatch を実装し、`cap.grant(resource, [ops], target)` を受け付けるようにした
   - 今後の改善:
     - explicit な ``delegatable`` フラグを CapabilitySet 側で扱う（現在は `is_permitted` を proxy している）
     - `grant` の監査ログ（発行者・証跡）を保存できる仕組み

3) 完全な Async-First 入力処理
   - 既に keyboard の `KeyboardStream` / `KeyEventFuture` を使うようにし、ポーリングを減らしました。
   - 次のステップ:
     - Mouse にも Future を追加（`MouseEventFuture`）、あるいは mouse driver が waker を登録できるようにする
     - `run_async_shell()` を `select`/`Stream` ベースにし、`keyboard`, `mouse`, `command_queue`, `timer` を同時に待つ設計にする（イベント駆動 -> CPU idle での低消費電力）

4) GUI の描画最適化
   - 提案:
     - 描画リクエストを "渇望キュー" に入れ、V-Sync（ディスプレイ更新）に合わせてバッチ処理
     - ダブルバッファを確実に使用し、フレームごとのフリップを実装
     - 部分更新（RectList）は維持しつつ、コンポジタが合成する時に最終的な合成領域を決定

移行ロードマップ（高レベル）
----------------------------

1. Capability の追加テストと audit（完了: 単体テスト追加済み）
2. 名前空間の動的登録（完了）
3. Keyboard IRQ-driven への移行（部分完了）
4. MouseFuture の追加（次タスク）
5. ExoBuffer/Shared buffer 型の導入（設計→小さい段階的変更→大規模置換）
6. GUI V-Sync 統合（フレームタイマーと compositor の実装）

互換性の考慮
-----------

- 既存スクリプトは `ExoValue::Bytes(Vec<u8>)` を想定していることがあるため、`ExoBuffer` を導入しても `to_vec()` / `to_owned_bytes()` で既存互換を確保する

追加のテスト/CI
---------------

- シミュレーション/ユニットテストで、Capability の委譲の境界条件を詳細に検証
- CI 上で `serena_audit` / `codacy_cli_analyze` を走らせて静的解析とポリシー準拠を確認

CI ワークフロー
----------------
このリポジトリにはホスト向けの自動テスト/リンターを追加しました: `.github/workflows/test.yml`。
ワークフローは以下を実行します:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test -p security`
- `cargo test -p cap_harness`
- `cargo test --manifest-path kernel/Cargo.toml --lib`

CI の audit ステップでは `serena_audit` / `codacy_cli_analyze` の CLI が利用可能であれば実行し、そうでない場合はスキップします。ローカルで同じチェックを実行するには、上のコマンドを順に実行してください。

参考実装スニペット
------------------

// ExoBuffer の概念スニペット

```rust
use alloc::sync::Arc;

pub enum ExoBuffer<'a> {
    Owned(Vec<u8>),
    Shared(Arc<[u8]>),
    Borrowed(&'a [u8]), // 将来的に RRef<'a, [u8]> に置換
}

impl<'a> ExoBuffer<'a> {
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            ExoBuffer::Owned(v) => v.clone(),
            ExoBuffer::Shared(a) => a.to_vec(),
            ExoBuffer::Borrowed(s) => s.to_vec(),
        }
    }
}
```

最後に
------

今回のパッチで、最優先のセキュリティ（cap.grant）と拡張性（動的 namespace 登録）、および入力の非同期化の初期改善を実装しました。次の段階（ゼロコピーバッファ、Mouse の Future 化、GUI の V-Sync）は設計が少し大きめなので、綿密な移行計画と追加のテストを作ってから実装することを推奨します。

質問や次の優先タスク（どれを実装しましょうか？）を教えてください。
