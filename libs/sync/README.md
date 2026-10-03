# libs/sync — 共有同期プリミティブ

- Status: Component detail / sync crate guide
- Audience: kernel と独立ビルドされる crate を実装する contributor
- Related: [ドキュメントハブ](../../docs/README.md), [開発ガイドライン](../../docs/kernel-development-guidelines.md), [アーキテクチャ概要](../../docs/architecture.md)

kernel と独立ビルドされる crate が共有する同期の境界を提供します。
kernel へ依存せず、共有資源の排他と通知の寿命を保つことを目的とします。

API と所有権の contract は [crate の定義](src/lib.rs)、CPU・割込みとの統合方針は
[Execution Fairness Reference](../../docs/reference/execution-fairness.md) を参照してください。

## 関連文書

- [../../docs/README.md](../../docs/README.md)
- [../../docs/kernel-development-guidelines.md](../../docs/kernel-development-guidelines.md)
