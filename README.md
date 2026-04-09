# ExoRust

- Status: Public landing page
- Audience: リポジトリを初めて開く開発者、設計方針を確認したい contributor
- Related: [ドキュメントハブ](docs/README.md), [アーキテクチャ概要](docs/architecture.md), [設計比較ガイド](docs/design-overview.md)

ExoRust は、Linux / POSIX 互換を前提にせず、Rust の所有権モデルと型安全性を中核に据えて設計する x86_64 向けカーネル研究プロジェクトです。

`docs/README.md` を唯一の総合入口として、canonical 文書、ADR、reference、runbook、archive を案内します。

## プロジェクト概要

- Single Address Space、Single Privilege Level、Async-First を前提に設計します。
- canonical baseline は [Variant A](docs/design_variants/variant-a-capability-first.md) です。
- Variant B / C は、PKS / MPK 系のハードウェア支援を追加する研究・将来拡張案として扱います。
- 権限制御の主軸は Capability、署名検証、IOMMU、Framework 境界です。

## 最短ルート

1. [docs/README.md](docs/README.md): 公開文書の総合入口
2. [docs/architecture.md](docs/architecture.md): 現行アーキテクチャの正本
3. [docs/decisions/README.md](docs/decisions/README.md): 採択済み設計判断
4. [docs/kernel-development-guidelines.md](docs/kernel-development-guidelines.md): 実装時の開発規約

## ビルドと検証

```bash
# カーネルのビルド
cargo build --target x86_64-exorust.json

# host 純テスト
cargo test

# full-boot QEMU required tier
cargo test -p qemu-tests fullboot_pr_required -- --exact --nocapture

# multicore smoke run
make smoke-multicore-vfio
```

詳細な boot 手順や検証条件は [docs/kernel-boot-sequence.md](docs/kernel-boot-sequence.md) と [bootloader/future-roadmap.md](bootloader/future-roadmap.md) を参照してください。

## 主要ディレクトリ

- `kernel/`: カーネル本体
- `interfaces/kernel_api/`: ドライバ / セル向けの公開 API
- `drivers/`: 独立ビルド可能なドライバ群
- `bootloader/`: ExoLoader
- `docs/`: canonical 文書、ADR、reference、runbook、proposal、archive
- `tools/`: ベンチ、補助スクリプト、検証用ツール

## 関連文書

- [docs/README.md](docs/README.md)
- [docs/architecture.md](docs/architecture.md)
- [docs/design-overview.md](docs/design-overview.md)
- [bootloader/future-roadmap.md](bootloader/future-roadmap.md)
