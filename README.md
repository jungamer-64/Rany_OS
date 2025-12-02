# ExoRust OS (Rany_OS)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-nightly-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-x86__64-blue.svg)](https://en.wikipedia.org/wiki/X86-64)

**ExoRust** は、Rustで実装された次世代Exokernel研究用オペレーティングシステムです。

## 🎯 設計理念

ExoRustは以下の革新的なアーキテクチャを採用しています：

### Single Address Space (SAS)
- 全プロセスが同一の仮想アドレス空間を共有
- TLBミスの大幅削減による高性能化
- ゼロコピーIPCの実現

### Single Privilege Level (SPL)
- リング0のみで動作し、システムコールオーバーヘッドを排除
- 型システムとRustの所有権モデルによる安全性保証
- 直接関数呼び出しによる高速なカーネル操作

### Async-First Design
- カーネル全体がasync/awaitベースで設計
- ワークスティーリングによる効率的なタスクスケジューリング
- ポーリングベースI/Oによる低レイテンシ

## 📁 プロジェクト構造

```
src/
├── allocator.rs       # グローバルアロケータ
├── domain_system.rs   # ドメイン管理システム
├── lib.rs            # ライブラリエントリ
├── main.rs           # カーネルエントリポイント
├── panic_handler.rs  # パニックハンドラ
├── smp.rs            # マルチコアサポート
├── spectre.rs        # Spectre対策
├── vga.rs            # VGAテキスト出力
│
├── domain/           # ドメイン（分離実行単位）
│   ├── lifecycle.rs  # ライフサイクル管理
│   └── registry.rs   # ドメインレジストリ
│
├── fs/               # ファイルシステム
│   ├── vfs.rs        # 仮想ファイルシステム
│   ├── block.rs      # ブロックデバイス抽象化
│   └── cache.rs      # バッファキャッシュ
│
├── interrupts/       # 割り込み処理
│   ├── gdt.rs        # GDT/TSS設定
│   └── exceptions.rs # 例外ハンドラ
│
├── io/               # I/Oサブシステム
│   ├── nvme.rs       # NVMeドライバ
│   ├── virtio.rs     # VirtIO基盤
│   ├── virtio_blk.rs # VirtIOブロック
│   ├── dma.rs        # DMA管理
│   ├── iommu.rs      # IOMMU制御
│   └── polling.rs    # ポーリングI/O
│
├── ipc/              # プロセス間通信
│   ├── rref.rs       # RRef（所有権転送IPC）
│   └── proxy.rs      # ドメイン間プロキシ
│
├── loader/           # ローダー
│   ├── elf.rs        # ELFローダー
│   └── signature.rs  # 署名検証
│
├── mm/               # メモリ管理
│   ├── buddy_allocator.rs   # バディアロケータ
│   ├── slab_cache.rs        # スラブキャッシュ
│   ├── frame_allocator.rs   # フレームアロケータ
│   ├── exchange_heap.rs     # Exchange Heap
│   ├── mapping.rs           # ページマッピング
│   └── per_cpu.rs           # Per-CPUデータ
│
├── net/              # ネットワーク
│   ├── tcp.rs        # TCPスタック
│   └── mempool.rs    # バッファプール
│
├── sas/              # SASサブシステム
│   ├── memory_region.rs   # メモリ領域管理
│   ├── ownership.rs       # 所有権追跡
│   └── heap_registry.rs   # ヒープレジストリ
│
├── sync/             # 同期プリミティブ
│   └── irq_mutex.rs  # 割り込み安全Mutex
│
├── task/             # タスク管理
│   ├── executor.rs       # 非同期Executor
│   ├── scheduler.rs      # スケジューラ
│   ├── work_stealing.rs  # ワークスティーリング
│   ├── preemption.rs     # プリエンプション
│   ├── timer.rs          # タイマー
│   ├── waker.rs          # Waker実装
│   └── context.rs        # コンテキスト切り替え
│
├── test/             # テストフレームワーク
│   ├── mod.rs            # テストランナー
│   ├── memory_tests.rs   # メモリテスト
│   ├── task_tests.rs     # タスクテスト
│   ├── network_tests.rs  # ネットワークテスト
│   ├── ipc_tests.rs      # IPCテスト
│   └── benchmark.rs      # パフォーマンスベンチマーク
│
├── demo/             # デモアプリケーション
│   ├── http_server.rs      # HTTPサーバー
│   ├── echo_server.rs      # エコーサーバー
│   └── performance_demo.rs # パフォーマンスデモ
│
└── monitor/          # システムモニター
    ├── display.rs    # 表示ユーティリティ
    └── collectors.rs # データコレクター
```

## 🚀 ビルド手順

### 必要条件

- Rust nightly (2024年以降推奨)
- `rust-src` コンポーネント
- QEMU (テスト用)

### セットアップ

```bash
# 1. Rust nightlyのインストール
rustup install nightly
rustup default nightly

# 2. 必要なコンポーネントの追加
rustup component add rust-src
rustup component add llvm-tools-preview

# 3. ビルド
cargo build --target x86_64-rany_os.json

# 4. QEMUで実行 (Windows)
.\run.ps1

# 4. QEMUで実行 (Linux/macOS)
./run.sh
```

## 🔧 開発オプション

### QEMU実行オプション

```powershell
# 基本実行
.\run.ps1

# デバッグモード
.\run.ps1 -Debug

# GDBデバッグ（ポート1234で待機）
.\run.ps1 -GDB

# ネットワーク有効
.\run.ps1 -Network

# カスタムメモリ/CPU
.\run.ps1 -Memory 1024 -Cpus 4
```

### Makefileターゲット

```bash
make build    # ビルド
make run      # QEMUで実行
make test     # テスト実行
make clean    # クリーン
```

## 📊 パフォーマンス特性

ExoRustは以下の領域で優れたパフォーマンスを実現：

| 操作 | 従来OS | ExoRust | 改善率 |
|------|--------|---------|--------|
| システムコール | ~200-500サイクル | ~10-20サイクル | 10-50x |
| IPC | ~1000サイクル | ~50サイクル | 20x |
| コンテキストスイッチ | ~1000サイクル | ~100サイクル | 10x |
| TLBミス | 高頻度 | 極低頻度 | - |

## 🧪 テスト

```bash
# 全テスト実行
cargo test

# 特定のテストモジュール
cargo test memory_tests
cargo test task_tests
cargo test network_tests
cargo test ipc_tests

# ベンチマーク
cargo bench
```

## 🎮 デモアプリケーション

### HTTPサーバー

ゼロコピーI/OによるHTTPサーバーのデモ：

```
GET /       - トップページ
GET /stats  - システム統計
GET /health - ヘルスチェック
GET /info   - システム情報
```

### エコーサーバー

TCP エコーサーバーによるネットワークスタックのデモ。

### パフォーマンスデモ

- システムコール排除の効果
- ゼロコピーバッファ転送
- TLB効率
- 非同期処理効率

## 🔒 セキュリティモデル

ExoRustは従来のハードウェア分離ではなく、以下のソフトウェアベースセキュリティを採用：

1. **Rustの型システム** - メモリ安全性を静的に保証
2. **所有権モデル** - データ競合の排除
3. **ドメイン分離** - 論理的な実行分離
4. **署名検証** - ローダーによるコード検証
5. **Spectre対策** - 投機実行攻撃への対処

## 📚 参考資料

- [Exokernel論文](https://pdos.csail.mit.edu/6.828/2008/readings/engler95exokernel.pdf)
- [RedLeaf OS](https://www.usenix.org/conference/osdi20/presentation/narayanan-vikram)
- [Theseus OS](https://www.usenix.org/conference/osdi20/presentation/boos)

## 🤝 コントリビューション

プルリクエストを歓迎します！以下のガイドラインに従ってください：

1. 新機能はテストを含めてください
2. `cargo fmt` でフォーマット
3. `cargo clippy` で警告がないことを確認
4. コミットメッセージは明確に

## 📄 ライセンス

MIT License - 詳細は [LICENSE](LICENSE) を参照

## 🙏 謝辞

- Rust言語チーム
- Philipp Oppermann の [blog_os](https://os.phil-opp.com/)
- Redox OS プロジェクト
- seL4 マイクロカーネル

---

**ExoRust** - Rustの力でオペレーティングシステムを再定義 🦀
