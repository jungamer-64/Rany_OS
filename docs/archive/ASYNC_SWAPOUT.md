# Async Swapout Removal Note

`async_swapout` / `zswap` / `page_reclaim` 系の設計は、ExoRust の現行アーキテクチャから外されました。

2026-03-18 時点のアクティブなメモリ管理面は次の最小構成です。

- SAS-only VM
- NUMA-aware allocation
- huge page
- page cache
- domain quota
- OOM killer

背景ワーカー型の reclaim / swap / shell namespace は維持しません。履歴として旧設計を参照する場合は、この文書を「削除済み機能のメモ」として扱ってください。
