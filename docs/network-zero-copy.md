# Zero-Copy Network API（ゼロコピー ネットワーク API）

概要
- 目的: アプリケーションから見て使いやすく、かつカーネル内部で"真のゼロコピー"が可能な非同期ネットワークAPIを提供する。
- 方針: アプリは高レベルの非同期API（send_async/recv_async や KAPI の send_packet/recv_packet）を使う。内部で可能なら PacketRef を使ったゼロコピー送信/受信を行い、失敗時は既存のコピー経路にフォールバックする。

主なコンポーネント
- PacketRef / Mempool
  - `kernel/src/net/mempool.rs` に定義。
  - 物理アドレスや容量、可変ビューを持つバッファ参照。所有権は PacketRef が保持し、解放は Drop で行われる。

- ZeroCopyWriter / ZeroCopySendFuture
  - `kernel/src/net/zero_copy.rs` にゼロコピー送信用ヘルパがある。`ZeroCopyWriter::enqueue_via_virtio(packet)` でデバイスに直接エンキューを試みる。
  - 成功すると PacketRef の所有権はデバイス側（tx_packetrefs）に移り、デバイスの TX 完了で unmap と解放が行われる。

- VirtIO ドライバ
  - `kernel/src/io/virtio/net.rs` にて `enqueue_send_zero_copy(packet)` を実装。IOMMU の必要な処理（バウンス / map）や DMA マスクチェックを行う。
  - TX 完了時に PacketRef のクリーンアップを行い、完了後に `NetworkEvent::TxAvailable` を発行してスタックに送信資源の解放を通知する。

非同期 API とバックプレッシャー
- ソケット: `OwnedSocket::send_async` と `SendFuture`
  - `SendFuture::poll` はまずソケット内部の送信バッファにデータを書き込む（可能分）。書き込み後に `NetworkEvent::DataReady` を送信し、ネットワークタスクが送信処理を行う。
  - 送信バッファがいっぱいの場合は waker を登録して Pending を返す。

フォールバックポリシー
- スタックはゼロコピーを優先する:
  - 可能なら `alloc_packet()` で PacketRef を取得して直接構築 → `enqueue_via_virtio(packet)` を呼び成功なら即座に完了。
  - エンキューに失敗（QueueFull や IOMMU エラー等）した場合は、落ち着いてコピー経路（既存のバッファ / tx_pool）を使用して送信する。
  - 補足: 互換API（`process_received_packet`）は削除され、ドライバや古いコードは新API（`process_received_packet_zero_copy`）を直接使用してください。

制約と注意点
- IRQ/ISR: 割り込み処理内で動的アロケーションは行わない。TX 完了処理は minimal なクリーンアップ（unmap 等）とイベント通知のみ行う。
- IOMMU: デバイスが IOMMU を要求する場合はバウンス領域を利用し、必要に応じて map/unmap を行う。失敗した場合はフォールバックする。
- 所有権: PacketRef の所有権は送信キューに入れる時点で移り、TX 完了で返却される（Drop が呼ばれる）。

開発 / テストのヒント
- 単体テスト:
  - `kernel/src/net/` に送信のフォールバック挙動を確認するユニットテストを追加済み。
- 統合テスト:
  - VirtIO モックを使って、enqueue が成功したときの tx_packetrefs の振る舞い、完了時の unmap と PacketRef の解放を検証してください。

FAQ（簡易）
- Q: いつゼロコピーを使うべき？
  - A: PacketRef がすぐに割り当てられる（メモリがある）かつデバイスキューに空きがあるとき。スタックは自動的に試行し、失敗時はコピーにフォールバックするため、アプリ側で特別な操作は不要です。

関連ファイル（参照）
- `kernel/src/net/mempool.rs`
- `kernel/src/net/zero_copy.rs`
- `kernel/src/io/virtio/net.rs`
- `kernel/src/net/stack.rs` (send_tcp/send_udp/send_icmp のゼロコピーパス)
- `kernel/src/net/endpoint/futures.rs` (SendFuture)

---
更新日: 2026-01-15
作成者: GitHub Copilot (Raptor mini (Preview))

## 🔁 テストの実行方法 (Integration)

Integration テストはカーネルターゲットと QEMU 上で実行する必要があります。以下の手順はリポジトリの推奨フローです：

1. 公式入口（required suites を実行）:

   ```bash
   cargo test
   ```

2. カーネル系のみを個別実行:

   ```bash
   cargo test -p qemu-tests -- --nocapture suite_kernel
   ```

3. 補助 E2E フロー（必要時のみ）:

   - Windows PowerShell 例（リポジトリに用意されているスクリプト）:
     `tools\e2e_zero_copy\run_e2e_qemu.ps1`

   - スクリプト側で必要なビルド/起動を実行し、QEMU の Serial 出力上にテストログを出力します。

> 注: 現在の公式テスト入口は `cargo test`（`qemu-tests` 経由）です。補助 E2E スクリプトは詳細検証用の追加手順として利用してください。
