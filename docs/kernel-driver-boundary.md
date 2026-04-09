# Kernel / Driver Boundary

- Status: Canonical layering rule
- Audience: ドライバ作者、カーネル統合担当、レビュー担当者
- Related: [ドキュメントハブ](README.md), [driver-dependency.md](driver-dependency.md), [architecture.md](architecture.md)

このドキュメントは、ExoRust におけるカーネルとドライバの責務境界を定義します。

## 原則

- `kernel` はフレームワーク層です。
  DMA/IOMMU、割り込み配送、実行器、ログ、セキュリティ、リソース管理を持ちます。
- `drivers/*` はデバイス層です。
  レジスタ定義、デバイス状態機械、キュー管理、プロトコル処理を持ちます。
- ドライバがカーネル機能を必要とする場合は `interfaces/kernel_api` 経由で要求します。
- 新しいカーネルコードは `crate::drivers::*` からデバイス機能にアクセスします。
- `crate::io::*` はカーネル所有の I/O インフラです。
  既存のドライバ互換 shim は残りますが、新規参照先としては使いません。

## 置き場所

`kernel` に置くもの:

- DMA / IOMMU のフレームワーク API
- ISR から executor への橋渡し
- `IoScheduler` や polling policy
- DriverRegistry / DriverDomain / Capability / Quota
- ドライバをカーネル実行系へ接続する薄い統合コード

`drivers/*` に置くもの:

- MMIO / port I/O を使ったデバイス制御本体
- デバイス固有の descriptor / command / queue 実装
- デバイス固有の probe / start / stop / remove
- カーネル内部型に依存しないエラー型と公開型

## 現在の公開境界

- ドライバ参照: `crate::drivers::{pci, acpi, virtio, nvme, ahci, hid, serial, audio, ...}`
- カーネル I/O 基盤: `crate::io::{dma, iommu, interrupt_manager, io_scheduler, log, mmio, port_io}`

## 例外

以下は「ドライバ本体」ではなく「カーネル統合アダプタ」として `kernel` 側に残します。

- `kernel/src/io/nvme/scheduler.rs`
- `kernel/src/io/ahci/poll_handler.rs`
- ドライバの global registry や boot-time orchestration

これらはデバイス仕様ではなく、カーネルの executor / scheduler / global state に結びつくためです。

## レビュー観点

- ドライバ crate から `kernel` crate へ依存していないか
- 新しい kernel コードが `crate::io::{ahci,nvme,virtio,...}` を直接参照していないか
- 追加 capability が必要なら `interfaces/kernel_api` に最小面積で追加しているか
- ドライバ内の unsafe が framework/HAL 境界に閉じているか

## 関連文書

- [README.md](README.md)
- [driver-dependency.md](driver-dependency.md)
- [../drivers/README.md](../drivers/README.md)
