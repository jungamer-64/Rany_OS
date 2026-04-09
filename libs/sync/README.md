# libs/sync — 外部クレート向け同期プリミティブ

- Status: Component detail / sync crate guide
- Audience: カーネル外部の crate を実装する contributor
- Related: [ドキュメントハブ](../../docs/README.md), [開発ガイドライン](../../docs/kernel-development-guidelines.md), [アーキテクチャ概要](../../docs/architecture.md)

## 概要

- 方針: `kernel/src/sync/` の依存を持ち込まず、移植しやすい同期プリミティブのサブセットを提供する

このクレートは、カーネル外部のクレート（独立ビルドされる storage / driver / tool 等）から使用可能な
**スタンドアロン版の同期プリミティブ** を提供します。

## kernel/src/sync/ との関係

| | `libs/sync` | `kernel/src/sync/` |
|---|---|---|
| **対象** | 外部クレート (fs, driver等) | カーネル内部 |
| **PoisonLock** | 基本版（`spin::Mutex` ベース） | 完全版（IRQ対応、デバッグ情報付き） |
| **Backoff** | 基本版 | 拡張版（`yield_limit` 付き） |
| **追加機能** | なし | `IrqMutex`, `AtomicWaker`, MPMC/MPSCリングバッファ, `BoundedChannel` 等 |

## 設計意図

カーネルの `sync/` モジュールはカーネル内部の API（割り込み制御、タスクスケジューラ等）に
依存しているため、外部クレートから直接使用できません。`libs/sync` はその依存を持たない
サブセット版として存在します。

API の互換性は意図的に維持されており、外部クレートのコードが将来カーネルに統合された際に
`use` 文の変更のみで移行できるようになっています。

## 使用例

```toml
# Cargo.toml
[dependencies]
exo_sync = { path = "../../libs/sync" }
```

```rust
use exo_sync::{PoisonLock, Backoff};
```

## 関連文書

- [../../docs/README.md](../../docs/README.md)
- [../../docs/kernel-development-guidelines.md](../../docs/kernel-development-guidelines.md)
