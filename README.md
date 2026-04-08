# ExoRust

- Status: Public landing page
- Audience: リポジトリを初めて開く開発者、設計方針を確認したい contributor
- Related: [ドキュメントハブ](docs/README.md), [アーキテクチャ概要](docs/ARCHITECTURE.md), [設計ハブ](docs/design-hub.md)

ExoRust は、Linux / POSIX 互換を前提にせず、Rust の所有権モデルと型安全性を中核に据えて設計する x86_64 向けカーネル研究プロジェクトです。

## プロジェクト概要

- Single Address Space、Single Privilege Level、Async-First を前提に設計します。
- canonical baseline は [Variant A](docs/design_variants/variant-a-capability-first.md) です。
- Variant B / C は、PKS / MPK 系のハードウェア支援を追加する研究・将来拡張案として扱います。
- 権限制御の主軸は Capability、署名検証、IOMMU、Framework 境界です。

## まず読む文書

- [docs/README.md](docs/README.md): 公開文書の全体索引
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): 現行アーキテクチャの正本
- [docs/kernel_development_guidelines.md](docs/kernel_development_guidelines.md): 実装時の開発規約
- [docs/design-hub.md](docs/design-hub.md): Variant A / B / C の位置付け比較

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

詳細な boot 手順や検証条件は [docs/kernel_boot_sequence.md](docs/kernel_boot_sequence.md) と
[bootloader/FUTURE_ROADMAP.md](bootloader/FUTURE_ROADMAP.md) を参照してください。

## リポジトリの見取り図

- `kernel/`: カーネル本体
- `interfaces/kernel_api/`: ドライバ / セル向けの公開 API
- `drivers/`: 独立ビルド可能なドライバ群
- `bootloader/`: ExoLoader
- `docs/`: 公開設計文書、リファレンス、runbook、履歴資料
- `tools/`: ベンチ、補助スクリプト、検証用ツール

## 関連文書

- [docs/README.md](docs/README.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/design-hub.md](docs/design-hub.md)
- [bootloader/FUTURE_ROADMAP.md](bootloader/FUTURE_ROADMAP.md)
